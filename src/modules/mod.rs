use crate::config::Config;
use crate::finding::Finding;
use crate::target::Target;
use anyhow::Result;
use std::sync::Arc;

pub mod cms;
pub mod cms_common;
pub mod cmsenum;
pub mod external;
pub mod nmap;
pub mod nuclei;
pub mod portscan;
pub mod recon;
pub mod secrets;
pub mod testssl;
pub mod tlsaudit;
pub mod web;
pub mod webvulns;

#[async_trait::async_trait]
#[allow(dead_code)]
pub trait Module: Send + Sync {
    fn name(&self) -> &'static str;
    fn description(&self) -> &'static str;
    async fn run(&self, target: &Target, config: &Config) -> Result<Vec<Finding>>;
}

pub fn enabled_modules(config: &Config) -> Vec<Arc<dyn Module>> {
    let mut modules: Vec<Arc<dyn Module>> = Vec::new();
    if config.modules.recon.enabled {
        modules.push(Arc::new(recon::Recon));
    }
    if config.modules.portscan.enabled {
        modules.push(Arc::new(portscan::Portscan));
    }
    if config.modules.web.enabled {
        modules.push(Arc::new(web::Web));
    }
    if config.modules.secrets.enabled {
        modules.push(Arc::new(secrets::Secrets));
    }
    if config.modules.nmap.enabled {
        modules.push(Arc::new(nmap::Nmap));
    }
    if config.modules.nuclei.enabled {
        modules.push(Arc::new(nuclei::Nuclei));
    }
    if config.modules.testssl.enabled {
        modules.push(Arc::new(testssl::Testssl));
    }
    if config.modules.cms.enabled {
        modules.push(Arc::new(cms::Cms));
    }
    if config.modules.tlsaudit.enabled {
        modules.push(Arc::new(tlsaudit::TlsAudit));
    }
    if config.modules.webvulns.enabled {
        modules.push(Arc::new(webvulns::WebVulns));
    }
    if config.modules.cmsenum.enabled {
        modules.push(Arc::new(cmsenum::CmsEnum));
    }
    modules
}
