// GuardUpload
// Criado em: 2025-11-01
// Licença: MIT
// Empresa: SoftCtrl

//! Motor de políticas responsável por decisões ALLOW/WARN/DENY.

use crate::config::{
    ArchivePolicySection, DefaultsSection, ImagePolicySection, PdfPolicySection, PolicyConfig,
};
use crate::report::{FileReport, PolicyDecision};
use crate::validators::{ValidatorOutcome, ValidatorStatus};

/// Resultado de decisão aplicável a um arquivo depois das validações.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Warn,
    Deny,
}

impl Decision {
    /// Converte a decisão em texto (`ALLOW`/`WARN`/`DENY`).
    pub fn as_str(&self) -> &'static str {
        match self {
            Decision::Allow => "ALLOW",
            Decision::Warn => "WARN",
            Decision::Deny => "DENY",
        }
    }

    /// Retorna severidade ordinal para comparação (maior é mais crítico).
    pub fn severity(&self) -> u8 {
        match self {
            Decision::Allow => 0,
            Decision::Warn => 1,
            Decision::Deny => 2,
        }
    }
}

/// Resultado completo da aplicação da política em um arquivo.
#[derive(Debug, Clone)]
pub struct DecisionOutcome {
    pub decision: Decision,
    pub rules_triggered: Vec<String>,
}

impl DecisionOutcome {
    pub fn new() -> Self {
        Self {
            decision: Decision::Allow,
            rules_triggered: Vec::new(),
        }
    }

    /// Registra regra acionada e eleva severidade conforme necessário.
    pub fn record(&mut self, severity: Decision, rule: impl Into<String>) {
        let rule_string = rule.into();
        self.rules_triggered.push(rule_string);
        if severity.severity() > self.decision.severity() {
            self.decision = severity;
        }
    }
}

impl Default for DecisionOutcome {
    fn default() -> Self {
        Self::new()
    }
}

impl From<DecisionOutcome> for PolicyDecision {
    fn from(value: DecisionOutcome) -> Self {
        PolicyDecision {
            decision: value.decision.as_str().to_string(),
            rules_triggered: value.rules_triggered,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct ResolvedPolicy {
    pub defaults: DefaultsSection,
    pub pdf: PdfPolicySection,
    pub image: ImagePolicySection,
    pub archive: ArchivePolicySection,
}

impl ResolvedPolicy {
    pub fn from_config(config: &PolicyConfig) -> Self {
        Self {
            defaults: config.defaults.clone(),
            pdf: config.pdf.clone(),
            image: config.image.clone(),
            archive: config.archive.clone(),
        }
    }
}

#[derive(Debug)]
struct CompiledPattern {
    raw: String,
    lowered: String,
}

impl CompiledPattern {
    fn new(raw: String) -> Self {
        let lowered = raw.to_ascii_lowercase();
        Self { raw, lowered }
    }

    fn matches(&self, value_lower: &str) -> bool {
        matches_pattern(&self.lowered, value_lower)
    }
}

#[derive(Debug, Default)]
struct CompiledDefaults {
    allow: Vec<CompiledPattern>,
    deny: Vec<CompiledPattern>,
    max_size_bytes: Option<u64>,
}

/// Executor de políticas carregadas a partir de YAML.
#[derive(Debug)]
pub struct PolicyEngine {
    config: PolicyConfig,
    compiled_defaults: CompiledDefaults,
}

impl PolicyEngine {
    /// Cria o motor a partir da configuração validada.
    pub fn new(config: PolicyConfig) -> Self {
        let compiled_defaults = compile_defaults(&config.defaults);
        Self {
            config,
            compiled_defaults,
        }
    }

    /// Resolve a política para um arquivo específico (aplica overrides futuros).
    pub fn resolve(&self, _report: &FileReport) -> ResolvedPolicy {
        // TODO: aplicar overrides baseadas em MIME/origem.
        ResolvedPolicy::from_config(&self.config)
    }

    /// Aplica decisão para um arquivo considerando validadores e limites.
    pub fn decide(
        &self,
        report: &FileReport,
        validators: &[ValidatorOutcome],
        resolved: Option<&ResolvedPolicy>,
    ) -> DecisionOutcome {
        let mut outcome = DecisionOutcome::new();

        for validator in validators {
            match validator.status {
                ValidatorStatus::Deny => {
                    outcome.record(Decision::Deny, format!("validator:{}:deny", validator.name))
                }
                ValidatorStatus::Warn => {
                    outcome.record(Decision::Warn, format!("validator:{}:warn", validator.name))
                }
                ValidatorStatus::Error => outcome.record(
                    Decision::Deny,
                    format!("validator:{}:error", validator.name),
                ),
                ValidatorStatus::Pass => {}
            }
        }

        let defaults = resolved
            .map(|policy| &policy.defaults)
            .unwrap_or(&self.config.defaults);
        let compiled = &self.compiled_defaults;
        let mime_lower = report.sniff.mime_real.to_ascii_lowercase();

        if let Some(max_size_mb) = defaults.max_size_mb {
            let max_bytes = max_size_mb as u64 * 1024 * 1024;
            if report.size_bytes > max_bytes {
                outcome.record(
                    Decision::Deny,
                    format!("size:exceeds_max:{}>{}", report.size_bytes, max_bytes),
                );
            }
        } else if let Some(max_bytes) = compiled.max_size_bytes {
            if report.size_bytes > max_bytes {
                outcome.record(
                    Decision::Deny,
                    format!("size:exceeds_max:{}>{}", report.size_bytes, max_bytes),
                );
            }
        }

        if let Some(pattern) = find_match(&compiled.deny, &mime_lower) {
            outcome.record(Decision::Deny, format!("mime:deny:{}", pattern.raw));
        }

        if !compiled.allow.is_empty() && find_match(&compiled.allow, &mime_lower).is_none() {
            outcome.record(
                Decision::Deny,
                format!("mime:not_allowed:{}", report.sniff.mime_real),
            );
        }

        outcome
    }

    /// Fornece referência à configuração original.
    pub fn config(&self) -> &PolicyConfig {
        &self.config
    }
}

fn compile_defaults(defaults: &DefaultsSection) -> CompiledDefaults {
    let allow = defaults
        .allow_types
        .iter()
        .map(|pattern| CompiledPattern::new(pattern.clone()))
        .collect();
    let deny = defaults
        .deny_types
        .iter()
        .map(|pattern| CompiledPattern::new(pattern.clone()))
        .collect();
    let max_size_bytes = defaults.max_size_mb.map(|mb| mb as u64 * 1024 * 1024);

    CompiledDefaults {
        allow,
        deny,
        max_size_bytes,
    }
}

fn find_match<'a>(
    patterns: &'a [CompiledPattern],
    value_lower: &str,
) -> Option<&'a CompiledPattern> {
    patterns.iter().find(|pattern| pattern.matches(value_lower))
}

fn matches_pattern(pattern: &str, value: &str) -> bool {
    matches_pattern_bytes(pattern.as_bytes(), value.as_bytes())
}

fn matches_pattern_bytes(pattern: &[u8], value: &[u8]) -> bool {
    if pattern.is_empty() {
        return value.is_empty();
    }

    match pattern[0] {
        b'*' => {
            let mut idx = 0;
            while idx < pattern.len() && pattern[idx] == b'*' {
                idx += 1;
            }
            if idx == pattern.len() {
                return true;
            }
            for offset in 0..=value.len() {
                if matches_pattern_bytes(&pattern[idx..], &value[offset..]) {
                    return true;
                }
            }
            false
        }
        b'?' => {
            if value.is_empty() {
                false
            } else {
                matches_pattern_bytes(&pattern[1..], &value[1..])
            }
        }
        ch => {
            if value.first() == Some(&ch) {
                matches_pattern_bytes(&pattern[1..], &value[1..])
            } else {
                false
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::{FileReport, SniffReport};
    use std::path::Path;

    #[test]
    fn decision_variants_match_strings() {
        assert_eq!(Decision::Allow.as_str(), "ALLOW");
        assert_eq!(Decision::Warn.as_str(), "WARN");
        assert_eq!(Decision::Deny.as_str(), "DENY");
    }

    #[test]
    fn decision_severity_orders_correctly() {
        assert!(Decision::Allow.severity() < Decision::Warn.severity());
        assert!(Decision::Warn.severity() < Decision::Deny.severity());
    }

    #[test]
    fn engine_holds_config_reference() {
        let config = PolicyConfig::default();
        let engine = PolicyEngine::new(config.clone());
        assert_eq!(
            engine.config().defaults.max_size_mb,
            config.defaults.max_size_mb
        );
    }

    #[test]
    fn deny_list_blocks_matching_mime() {
        let mut config = PolicyConfig::default();
        config.defaults.deny_types = vec!["application/x-rpm".into()];
        let engine = PolicyEngine::new(config);
        let report = sample_report("application/x-rpm", 1024);
        let outcome = engine.decide(&report, &[], None);
        assert_eq!(outcome.decision, Decision::Deny);
        assert!(outcome
            .rules_triggered
            .iter()
            .any(|rule| rule == "mime:deny:application/x-rpm"));
    }

    #[test]
    fn allow_list_denies_when_mime_absent() {
        let mut config = PolicyConfig::default();
        config.defaults.allow_types = vec!["image/*".into(), "application/pdf".into()];
        let engine = PolicyEngine::new(config);
        let report = sample_report("video/mp4", 2048);
        let outcome = engine.decide(&report, &[], None);
        assert_eq!(outcome.decision, Decision::Deny);
        assert!(outcome
            .rules_triggered
            .iter()
            .any(|rule| rule == "mime:not_allowed:video/mp4"));
    }

    #[test]
    fn allow_list_matches_wildcard() {
        let mut config = PolicyConfig::default();
        config.defaults.allow_types = vec!["image/*".into()];
        let engine = PolicyEngine::new(config);
        let report = sample_report("image/png", 512);
        let outcome = engine.decide(&report, &[], None);
        assert_eq!(outcome.decision, Decision::Allow);
    }

    #[test]
    fn size_limit_triggers_deny() {
        let mut config = PolicyConfig::default();
        config.defaults.max_size_mb = Some(1);
        let engine = PolicyEngine::new(config);
        let report = sample_report("application/pdf", 2 * 1024 * 1024);
        let outcome = engine.decide(&report, &[], None);
        assert_eq!(outcome.decision, Decision::Deny);
        assert!(outcome
            .rules_triggered
            .iter()
            .any(|rule| rule.starts_with("size:exceeds_max:")));
    }

    #[test]
    fn validator_denies_propagate_to_policy() {
        let config = PolicyConfig::default();
        let engine = PolicyEngine::new(config);
        let report = sample_report("application/pdf", 1024);
        let validator = ValidatorOutcome::deny("pdf", "teste");
        let outcome = engine.decide(&report, &[validator], None);
        assert_eq!(outcome.decision, Decision::Deny);
        assert!(outcome
            .rules_triggered
            .iter()
            .any(|rule| rule.starts_with("validator:pdf")));
    }

    fn sample_report(mime: &str, size: u64) -> FileReport {
        let sniff = SniffReport::new(mime.to_string(), None, None);
        FileReport::new(Path::new("sample.bin"), size, "deadbeef".into(), sniff)
    }
}
