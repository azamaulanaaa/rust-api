use actix_web::web;

mod auth;
mod health;

pub fn config(cfg: &mut web::ServiceConfig) {
    cfg.service(health::health)
        .service(web::scope("/auth").configure(auth::config));
}
