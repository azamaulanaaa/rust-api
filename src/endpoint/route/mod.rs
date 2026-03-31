use actix_web::web;

mod health;

pub fn config(cfg: &mut web::ServiceConfig) {
    cfg.service(health::health);
}
