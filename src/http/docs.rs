//! The OpenAPI JSON document and the Swagger UI.

use actix_web::web;
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

use crate::docs::ApiDoc;

/// Mounts `/openapi.json` and `/swagger-ui/*` from the compiled `ApiDoc`.
///
/// [`SwaggerUi`] uses absolute paths, so the code registers it directly on
/// the `ServiceConfig`.
///
/// The code used to wrap this module in a `web::scope("")`. That scope is
/// both redundant and destructive. A scope with an empty prefix matches every
/// request, so the scope hid every service that was registered after it.
/// This module is mounted before the API modules, so the scope returned 404
/// for every `/fs`, `/policy`, `/auth`, `/sync`, and `/setup` route on the
/// real server, while `/health`, `/ready`, and the spec itself still
/// answered. The OpenAPI test only checked that the paths were *declared*.
/// No test checked that the paths were *mounted*, and no test ran the
/// composition root.
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
