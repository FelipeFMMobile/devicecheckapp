package com.fmmobile.bookservice.book.book.configuration

import io.swagger.v3.oas.annotations.OpenAPIDefinition
import io.swagger.v3.oas.models.Components
import io.swagger.v3.oas.models.OpenAPI
import io.swagger.v3.oas.models.info.License
import org.springframework.context.annotation.Bean

@OpenAPIDefinition()
class OpenApiConfiguration {

    @Bean
    public fun customOpenAPI() : OpenAPI {
        return OpenAPI()
            .components(Components())
            .info(io.swagger.v3.oas.models.info.Info()
                .title("Attest Service API")
                .version("v1")
                .license(License()
                    .name("Apache 2.0")
                    .url("https://springdoc.org"))
            )
    }
}
