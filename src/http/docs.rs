//! OpenAPI JSON + Swagger UI.

use actix_web::web;
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

use crate::docs::ApiDoc;

/// Mounts `/openapi.json` and `/swagger-ui/*` from the compiled `ApiDoc`.
pub fn config(cfg: &mut web::ServiceConfig) {
    let openapi = ApiDoc::openapi();
    cfg.service(
        web::scope("").service(
            SwaggerUi::new("/swagger-ui/{_:.*}")
                .url("/openapi.json", openapi)
                .config(utoipa_swagger_ui::Config::default()),
        ),
    );
}
