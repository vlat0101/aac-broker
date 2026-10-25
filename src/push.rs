//! Pushover doorbell.
//!
//! Deliberately dumb: it carries the request facts and a link, never a decision.
//! Pushover has no inline action buttons, and a notification that can approve
//! something is a notification you can approve by accident.

use std::time::Duration;

/// Configured notifier. Constructed from the environment so the systemd unit
/// can source it from the vault-backed env file; absent keys mean "no push".
#[derive(Clone)]
pub struct Pushover {
    token: String,
    user: String,
    /// Pushover sound name. Default is a soft one: the doorbell should be
    /// noticeable, not alarming. Override with PUSHOVER_SOUND.
    sound: String,
    /// Pushover priority: -2..2. Default 0 (normal). Priority 1 bypasses quiet
    /// hours, which is louder than it sounds — only raise it deliberately.
    priority: String,
}

impl Pushover {
    pub fn from_env() -> Option<Self> {
        let token = std::env::var("PUSHOVER_TOKEN").ok().filter(|s| !s.is_empty())?;
        let user = std::env::var("PUSHOVER_USER").ok().filter(|s| !s.is_empty())?;
        Some(Self::with_options(
            token,
            user,
            std::env::var("PUSHOVER_SOUND").ok(),
            std::env::var("PUSHOVER_PRIORITY").ok(),
        ))
    }

    /// Pure constructor: applies the calm defaults and rejects nonsense values.
    /// Kept free of environment reads so it can be tested without racing.
    fn with_options(token: String, user: String, sound: Option<String>, priority: Option<String>) -> Self {
        let sound = sound
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| "bike".to_string());
        let priority = priority
            .filter(|s| matches!(s.as_str(), "-2" | "-1" | "0" | "1" | "2"))
            .unwrap_or_else(|| "0".to_string());
        Self {
            token,
            user,
            sound,
            priority,
        }
    }

    /// Fire and forget from a blocking thread — callers are in an async loop.
    pub fn notify(&self, title: &str, body: &str, url: Option<&str>) {
        let this = self.clone();
        let (t, b, u) = (
            title.to_string(),
            body.to_string(),
            url.map(str::to_string),
        );
        std::thread::spawn(move || {
            let mut form: Vec<(&str, &str)> = vec![
                ("token", this.token.as_str()),
                ("user", this.user.as_str()),
                ("title", t.as_str()),
                ("message", b.as_str()),
                // Configurable, defaulting to normal priority and a light
                // sound: a request is a nudge, and the page is the real gate.
                ("priority", this.priority.as_str()),
                ("sound", this.sound.as_str()),
            ];
            if let Some(url) = u.as_deref() {
                form.push(("url", url));
                form.push(("url_title", "Open approval page"));
            }
            let agent = ureq::AgentBuilder::new()
                .timeout(Duration::from_secs(10))
                .build();
            let _ = agent
                .post("https://api.pushover.net/1/messages.json")
                .send_form(&form);
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_calm_not_alarming() {
        let p = Pushover::with_options("t".into(), "u".into(), None, None);
        assert_eq!(p.sound, "bike");
        assert_eq!(p.priority, "0");
    }

    #[test]
    fn overrides_are_honoured_but_bad_priority_falls_back() {
        let p = Pushover::with_options(
            "t".into(),
            "u".into(),
            Some("glass".into()),
            Some("1".into()),
        );
        assert_eq!(p.sound, "glass");
        assert_eq!(p.priority, "1");
        let bad = Pushover::with_options(
            "t".into(),
            "u".into(),
            Some("  ".into()),
            Some("9".into()),
        );
        assert_eq!(bad.sound, "bike");
        assert_eq!(bad.priority, "0");
    }

    #[test]
    fn absent_env_means_no_notifier_rather_than_a_broken_one() {
        // Both vars unset in the test env: no notifier, no panic, no half-configured state.
        if std::env::var("PUSHOVER_TOKEN").is_err() || std::env::var("PUSHOVER_USER").is_err() {
            assert!(Pushover::from_env().is_none());
        }
    }
}
