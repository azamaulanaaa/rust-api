//! OpenAPI JSON + Swagger UI.

use actix_web::web;
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

use crate::docs::ApiDoc;

/// Mounts `/openapi.json` and `/swagger-ui/*` from the compiled `ApiDoc`.
///
/// [`SwaggerUi`] carries absolute paths, so it is registered directly on
/// the `ServiceConfig`.
///
/// It used to be wrapped in a `web::scope("")`, which is redundant *and*
/// destructive: an empty-prefix scope matches every request, so it
/// shadowed every service registered after it. Because this module is
/// mounted before the API modules, that silently 404'd every `/fs`,
/// `/policy`, `/auth`, `/sync`, and `/setup` route in the real server
/// while `/health`, `/ready`, and the spec itself still answered. The
/// OpenAPI test only checked that paths were *declared*, never that they
/// were *mounted*, and no test exercised the composition root.
///
/// [`SwaggerUi`]: utoipa_swagger_ui::SwaggerUi
pub fn config(cfg: &mut web::ServiceConfig) {
    let openapi = ApiDoc::openapi();
    cfg.service(
        SwaggerUi::new("/swagger-ui/{_:.*}")
            .url("/openapi.json", openapi)
            .config(utoipa_swagger_ui::Config::default()),
    );
}
