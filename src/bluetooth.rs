//! Cross-platform BLE central adapter for the native ClipTown desktop client.
//!
//! The adapter discovers and connects to the same GATT service as the Flutter
//! client on Windows, macOS, and Linux. It transports only bounded proximity
//! frames; enrolled-device verification, replay checks, consent, and decryption
//! remain mandatory callers of [`crate::proximity`].

use std::{collections::HashMap, pin::Pin, time::Duration};

use anyhow::{Context as _, Result, anyhow, ensure};
use btleplug::{
    api::{
        Central as _, Characteristic, Manager as _, Peripheral as _, ScanFilter, ValueNotification,
        WriteType,
    },
    platform::{Adapter, Manager, Peripheral},
};
use futures::{Stream, StreamExt as _};
use uuid::Uuid;

use crate::proximity::{
    BleFrameReassembler, ProximityAdvertisement, SERVICE_UUID, fragment_ble_message,
};

const ADVERTISEMENT_CHARACTERISTIC_UUID: Uuid =
    Uuid::from_u128(0xc11f7a00_7b9e_4d8a_9c3a_4b8a0d86e002);
const INBOUND_CHARACTERISTIC_UUID: Uuid = Uuid::from_u128(0xc11f7a00_7b9e_4d8a_9c3a_4b8a0d86e003);
const OUTBOUND_CHARACTERISTIC_UUID: Uuid = Uuid::from_u128(0xc11f7a00_7b9e_4d8a_9c3a_4b8a0d86e004);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BluetoothCandidate {
    /// Process-local route handle. Never persist or treat it as device identity.
    pub transport_id: String,
    pub display_name: String,
    pub rssi: Option<i16>,
}

pub struct BluetoothCentral {
    adapter: Adapter,
    candidates: HashMap<String, Peripheral>,
}

impl BluetoothCentral {
    pub async fn new() -> Result<Self> {
        let manager = Manager::new()
            .await
            .context("initialize operating-system Bluetooth manager")?;
        let adapter = manager
            .adapters()
            .await
            .context("enumerate Bluetooth adapters")?
            .into_iter()
            .next()
            .ok_or_else(|| anyhow!("no Bluetooth adapter is available"))?;
        Ok(Self {
            adapter,
            candidates: HashMap::new(),
        })
    }

    /// Perform one bounded, foreground discovery window.
    pub async fn discover(&mut self, window: Duration) -> Result<Vec<BluetoothCandidate>> {
        ensure!(
            (Duration::from_secs(1)..=Duration::from_secs(30)).contains(&window),
            "Bluetooth discovery window is outside reviewed bounds"
        );
        self.candidates.clear();
        self.adapter
            .start_scan(ScanFilter {
                services: vec![SERVICE_UUID],
            })
            .await
            .context("start ClipTown BLE discovery")?;
        tokio::time::sleep(window).await;
        let discovered = self
            .adapter
            .peripherals()
            .await
            .context("collect ClipTown BLE candidates")?;
        self.adapter
            .stop_scan()
            .await
            .context("stop ClipTown BLE discovery")?;

        let mut result = Vec::new();
        for peripheral in discovered {
            let Some(properties) = peripheral.properties().await? else {
                continue;
            };
            let name = properties
                .local_name
                .or(properties.advertisement_name)
                .unwrap_or_default();
            let has_service = properties.services.contains(&SERVICE_UUID);
            if !has_service && !valid_display_name(&name) {
                continue;
            }
            let display_name = if valid_display_name(&name) {
                name
            } else {
                "ClipTown nearby device".to_owned()
            };
            let transport_id = peripheral.id().to_string();
            self.candidates
                .insert(transport_id.clone(), peripheral.clone());
            result.push(BluetoothCandidate {
                transport_id,
                display_name,
                rssi: properties.rssi,
            });
        }
        result.sort_by(|left, right| right.rssi.cmp(&left.rssi));
        Ok(result)
    }

    pub async fn connect(&self, transport_id: &str) -> Result<BluetoothSession> {
        let peripheral = self
            .candidates
            .get(transport_id)
            .cloned()
            .ok_or_else(|| anyhow!("selected peer was not discovered in this process"))?;
        peripheral
            .connect_with_timeout(Duration::from_secs(15))
            .await
            .context("connect to selected ClipTown BLE peer")?;
        peripheral
            .discover_services_with_timeout(Duration::from_secs(10))
            .await
            .context("discover ClipTown GATT service")?;
        let characteristics = peripheral.characteristics();
        let find = |uuid| {
            characteristics
                .iter()
                .find(|candidate| candidate.service_uuid == SERVICE_UUID && candidate.uuid == uuid)
                .cloned()
        };
        let advertisement = find(ADVERTISEMENT_CHARACTERISTIC_UUID)
            .ok_or_else(|| anyhow!("ClipTown advertisement characteristic is missing"))?;
        let inbound = find(INBOUND_CHARACTERISTIC_UUID)
            .ok_or_else(|| anyhow!("ClipTown inbound characteristic is missing"))?;
        let outbound = find(OUTBOUND_CHARACTERISTIC_UUID)
            .ok_or_else(|| anyhow!("ClipTown outbound characteristic is missing"))?;
        peripheral
            .subscribe(&outbound)
            .await
            .context("subscribe to encrypted ClipTown BLE frames")?;
        let notifications = peripheral
            .notifications()
            .await
            .context("open ClipTown BLE notification stream")?;
        Ok(BluetoothSession {
            peripheral,
            advertisement,
            inbound,
            outbound,
            notifications,
            reassembler: BleFrameReassembler::new(8).map_err(|error| anyhow!(error.to_string()))?,
        })
    }
}

pub struct BluetoothSession {
    peripheral: Peripheral,
    advertisement: Characteristic,
    inbound: Characteristic,
    outbound: Characteristic,
    notifications: Pin<Box<dyn Stream<Item = ValueNotification> + Send>>,
    reassembler: BleFrameReassembler,
}

impl BluetoothSession {
    pub async fn read_advertisement(&self) -> Result<ProximityAdvertisement> {
        let bytes = self
            .peripheral
            .read(&self.advertisement)
            .await
            .context("read rotating ClipTown advertisement")?;
        ensure!(
            bytes.len() <= 512,
            "ClipTown advertisement exceeds size limit"
        );
        let advertisement: ProximityAdvertisement =
            serde_json::from_slice(&bytes).context("parse ClipTown advertisement")?;
        advertisement
            .validate()
            .map_err(|error| anyhow!(error.to_string()))?;
        Ok(advertisement)
    }

    pub async fn send_encrypted(&self, envelope: &[u8]) -> Result<()> {
        let mtu_payload = usize::from(self.peripheral.mtu().saturating_sub(3));
        let packet_bytes = mtu_payload.clamp(20, 185);
        for packet in fragment_ble_message(envelope, packet_bytes)
            .map_err(|error| anyhow!(error.to_string()))?
        {
            self.peripheral
                .write(&self.inbound, &packet, WriteType::WithResponse)
                .await
                .context("write encrypted ClipTown BLE frame")?;
        }
        Ok(())
    }

    pub async fn receive_encrypted(
        &mut self,
        now_unix_ms: impl Fn() -> u64,
        timeout: Duration,
    ) -> Result<Vec<u8>> {
        let receive = async {
            while let Some(notification) = self.notifications.next().await {
                if notification.uuid != self.outbound.uuid {
                    continue;
                }
                match self
                    .reassembler
                    .add(&notification.value, now_unix_ms())
                    .map_err(|error| anyhow!(error.to_string()))?
                {
                    Some(message) => return Ok(message),
                    None => continue,
                }
            }
            Err(anyhow!("ClipTown BLE peer disconnected"))
        };
        tokio::time::timeout(timeout, receive)
            .await
            .context("timed out waiting for encrypted ClipTown BLE frame")?
    }

    pub async fn close(mut self) -> Result<()> {
        self.reassembler.clear();
        let _ = self.peripheral.unsubscribe(&self.outbound).await;
        self.peripheral
            .disconnect()
            .await
            .context("disconnect ClipTown BLE peer")
    }
}

fn valid_display_name(value: &str) -> bool {
    value.len() == 9
        && value.starts_with("CT-")
        && value[3..]
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_names_are_rotating_and_bounded() {
        assert!(valid_display_name("CT-A1b2_3"));
        assert!(!valid_display_name("ClipTown-alex-laptop"));
        assert!(!valid_display_name("CT-too-long"));
    }
}
