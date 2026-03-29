mod auth;
mod health;

use actix_web::web;

pub fn config(cfg: &mut web::ServiceConfig) {
    cfg.service(health::health)
        .service(web::scope("/auth").configure(auth::config));
}
