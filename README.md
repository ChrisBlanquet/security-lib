# Security Lib - Ayuntamiento

Librería base de seguridad centralizada para el ecosistema de microservicios. Este SDK proporciona la configuración estándar de Spring Security y la validación de tokens JWT para asegurar que todas las peticiones a la API estén debidamente autenticadas.

## Características Principales

* **Configuración Centralizada:** Estandariza las reglas de Spring Security para todos los microservicios que la importen.
* **Validación JWT:** Contiene los filtros necesarios (`JwtAuthenticationFilter`) para interceptar peticiones, extraer el token Bearer y validar su firma.
* **Manejo de Excepciones:** Gestiona respuestas estandarizadas (EntryPoint) cuando un usuario no está autorizado (Error 401).
* **Plug & Play:** Diseñada para ser importada sin requerir configuraciones complejas en cada microservicio cliente.

## Instalación (GitHub Packages)

Esta librería está alojada en GitHub Packages de forma privada. Para utilizarla en tu microservicio, sigue estos dos pasos:

### 1. Configurar Credenciales Maven
Debes tener un Token de Acceso Personal (PAT) de GitHub con el permiso `read:packages`. Agrega este token en el archivo `settings.xml` de tu carpeta `.m2` local:

<settings>
    <servers>
        <server>
            <id>github</id>
            <username>TU_USUARIO_DE_GITHUB</username>
            <password>ghp_TU_TOKEN_AQUI</password>
        </server>
    </servers>
</settings>

### 2. Agregar la Dependencia
En el archivo `pom.xml` del microservicio cliente, asegúrate de tener el repositorio configurado y agrega la dependencia:

<repositories>
    <repository>
        <id>github</id>
        <url>https://maven.pkg.github.com/ChrisBlanquet/security-lib</url>
    </repository>
</repositories>

<dependencies>
    <dependency>
        <groupId>com.ayuntamiento</groupId>
        <artifactId>security-lib</artifactId>
        <version>0.0.1-SNAPSHOT</version>
    </dependency>
</dependencies>

## Uso Rápido

Una vez instalada la dependencia, el microservicio heredará automáticamente la validación de tokens. Asegúrate de tener en el `application.properties` del microservicio cliente la misma clave pública o secreto para validar los JWT (dependiendo de tu implementación criptográfica).

## Tecnologías Utilizadas

* Java 21
* Spring Boot 3.x
* Spring Security
* jjwt (JSON Web Token)
* Lombok
