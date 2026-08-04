//! Waking a device that is not connected — `DESIGN.md` §12.2.
//!
//! **The wake-up carries nothing.** Signal's design: the home server tells the
//! platform's push service that a device has something waiting; the device wakes,
//! connects to its own home server, fetches, and decrypts locally, building the
//! notification itself. Apple and Google learn *that* a device had something and
//! when — never content, never sender.
//!
//! # Contentlessness is enforced by the type, not by discipline
//!
//! [`Gateway::wake`] takes a device and a token and **nothing else**. There is no
//! parameter a message could be passed through, so a future caller cannot leak
//! content into a push by being careless — it would have to change this trait
//! first, which is a conversation rather than an accident.
//!
//! §12.2 calls contentless push "architectural and not optional", and this is
//! what that sentence has to mean in code. A gateway that accepted a body would
//! make the guarantee a convention, and conventions erode.
//!
//! # What is not here
//!
//! **No APNs or FCM transport.** Both need credentials, a signed application and
//! a device to receive on, none of which exist here and none of which can be
//! exercised from a desktop. What exists is the path — registration, the decision
//! to wake, and the boundary a transport plugs into — so adding one is writing an
//! HTTP request against a documented API rather than threading a new concept
//! through the server.
//!
//! Polling (§12.2) is the half that works today, and is deliberately the half
//! that matters for §1.3: it is what stops a push gateway becoming a dependency.

use anyhow::Result;
use veil_protocol::identity::DeviceAddress;

/// Which platform service wakes a device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Service {
	Apns,
	Fcm,
}

impl Service {
	pub fn parse(name: &str) -> Option<Self> {
		match name.to_ascii_lowercase().as_str() {
			"apns" => Some(Self::Apns),
			"fcm" => Some(Self::Fcm),
			_ => None,
		}
	}

	pub fn name(&self) -> &'static str {
		match self {
			Self::Apns => "apns",
			Self::Fcm => "fcm",
		}
	}
}

/// Somewhere a wake-up can be sent.
///
/// Note what this cannot do: there is no way to pass it anything about the
/// message. That is the contentless guarantee, expressed where it cannot be
/// forgotten.
pub trait Gateway: Send + Sync {
	fn wake(&self, device: DeviceAddress, service: Service, token: &str) -> Result<()>;
}

/// The gateway a server without push credentials uses.
///
/// Does nothing and says so once. A host with no push configuration is the
/// ordinary case for a self-hoster (§1.3), and it must not be a broken host —
/// its users poll instead, which costs latency and buys resistance to timing
/// correlation.
pub struct NotConfigured;

impl Gateway for NotConfigured {
	fn wake(&self, _device: DeviceAddress, _service: Service, _token: &str) -> Result<()> {
		Ok(())
	}
}

/// Records wake-ups instead of sending them.
///
/// Used by tests, and kept out of `cfg(test)` so a real gateway added later has
/// a worked example of the trait beside it rather than in a test module.
#[allow(dead_code)]
///
/// Used by the tests to check that a device *would* be woken, and that nothing
/// about the message travels with it.
pub struct Recording {
	pub woken: std::sync::Mutex<Vec<(DeviceAddress, Service, String)>>,
}

impl Recording {
	#[allow(dead_code)]
	pub fn new() -> Self {
		Self {
			woken: std::sync::Mutex::new(Vec::new()),
		}
	}
}

impl Gateway for Recording {
	fn wake(&self, device: DeviceAddress, service: Service, token: &str) -> Result<()> {
		self.woken
			.lock()
			.unwrap()
			.push((device, service, token.to_owned()));
		Ok(())
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use veil_protocol::{crosssign::CrossSigningSecrets, identity::DeviceId};

	fn device() -> DeviceAddress {
		DeviceAddress::new(CrossSigningSecrets::new().user_id(), DeviceId::generate())
	}

	/// A host with no push configuration is the ordinary self-hosted case and
	/// must work, not fail (§1.3).
	#[test]
	fn a_host_without_push_still_works() {
		assert!(NotConfigured.wake(device(), Service::Apns, "token").is_ok());
	}

	#[test]
	fn a_gateway_is_told_which_device_to_wake() {
		let gateway = Recording::new();
		let target = device();

		gateway.wake(target, Service::Fcm, "abc123").unwrap();

		let woken = gateway.woken.lock().unwrap();
		assert_eq!(woken.len(), 1);
		assert_eq!(woken[0].0, target);
		assert_eq!(woken[0].1, Service::Fcm);
	}

	/// A wake-up is a device, a service and the device's own token.
	///
	/// The contentlessness §12.2 calls architectural is enforced by
	/// `Gateway::wake` having no parameter a message could travel through, and a
	/// test cannot strengthen that — there is no way to pass content in, so
	/// there is no failing case to write. This records the shape so that adding
	/// such a parameter is a visible change here rather than a quiet one.
	#[test]
	fn a_wake_up_is_only_a_device_and_its_token() {
		let gateway = Recording::new();
		let target = device();
		gateway
			.wake(target, Service::Apns, "the device's own token")
			.unwrap();

		assert_eq!(
			*gateway.woken.lock().unwrap(),
			vec![(target, Service::Apns, "the device's own token".to_owned())]
		);
	}

	#[test]
	fn service_names_round_trip() {
		for service in [Service::Apns, Service::Fcm] {
			assert_eq!(Service::parse(service.name()), Some(service));
		}
		assert_eq!(Service::parse("carrier pigeon"), None);
	}
}
