use actix_web::web;

mod health;

/// Registers the built-in routes shared by every deployment.
pub fn config(cfg: &mut web::ServiceConfig) {
    cfg.service(health::health);
}
