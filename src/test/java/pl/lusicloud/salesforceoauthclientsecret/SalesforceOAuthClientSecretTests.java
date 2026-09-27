package pl.lusicloud.salesforceoauthclientsecret;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import okhttp3.Credentials;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;

import org.junit.jupiter.api.Test;

class SalesforceOAuthClientSecretTests {

  @Test
  void authenticatesLazilyAndRequestsANewTokenAfterUnauthorized() throws Exception {
    AtomicInteger tokenCount = new AtomicInteger();
    AtomicInteger requestCount = new AtomicInteger();
    List<String> tokenAuthorizationHeaders = new ArrayList<>();
    List<String> tokenRequestBodies = new ArrayList<>();
    List<String> apiAuthorizationHeaders = new ArrayList<>();
    HttpServer fakeSalesforce = HttpServer.create(new InetSocketAddress("localhost", 0), 0);
    fakeSalesforce.createContext("/services/oauth2/token", exchange -> {
      int tokenNumber = tokenCount.incrementAndGet();
      tokenAuthorizationHeaders.add(exchange.getRequestHeaders().getFirst("Authorization"));
      tokenRequestBodies.add(new String(
          exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
      respond(exchange, 200, "{\"access_token\":\"test-access-token-" + tokenNumber + "\"}");
    });
    fakeSalesforce.createContext("/services/data", exchange -> {
      apiAuthorizationHeaders.add(exchange.getRequestHeaders().getFirst("Authorization"));
      int requestNumber = requestCount.incrementAndGet();
      respond(exchange, requestNumber == 2 ? 401 : 200, "ok");
    });
    fakeSalesforce.start();

    try {
      String domain = "http://localhost:" + fakeSalesforce.getAddress().getPort();
      OkHttpClient client = SalesforceOAuthClientSecret.authenticate(
          "test-client-id", "test-client-secret", domain);
      assertEquals(0, tokenCount.get());

      try (Response response = client.newCall(
          new Request.Builder().url(domain + "/services/data").build()).execute()) {
        assertTrue(response.isSuccessful());
      }
      try (Response response = client.newCall(
          new Request.Builder().url(domain + "/services/data").build()).execute()) {
        assertTrue(response.isSuccessful());
      }

      assertEquals(2, tokenCount.get());
      assertEquals(List.of(
          Credentials.basic("test-client-id", "test-client-secret", StandardCharsets.UTF_8),
          Credentials.basic("test-client-id", "test-client-secret", StandardCharsets.UTF_8)),
          tokenAuthorizationHeaders);
      assertEquals(List.of(
          "grant_type=client_credentials",
          "grant_type=client_credentials"), tokenRequestBodies);
      assertEquals(List.of(
          "Bearer test-access-token-1",
          "Bearer test-access-token-1",
          "Bearer test-access-token-2"), apiAuthorizationHeaders);
    } finally {
      fakeSalesforce.stop(0);
    }
  }

  @Test
  void doesNotAuthenticateOrSendCredentialsToAnotherOrigin() throws Exception {
    AtomicInteger tokenCount = new AtomicInteger();
    AtomicReference<String> foreignAuthorizationHeader = new AtomicReference<>();
    HttpServer fakeSalesforce = HttpServer.create(new InetSocketAddress("localhost", 0), 0);
    fakeSalesforce.createContext("/services/oauth2/token", exchange -> {
      tokenCount.incrementAndGet();
      respond(exchange, 200, "{\"access_token\":\"test-access-token\"}");
    });
    fakeSalesforce.start();

    HttpServer foreignServer = HttpServer.create(new InetSocketAddress("localhost", 0), 0);
    foreignServer.createContext("/foreign", exchange -> {
      foreignAuthorizationHeader.set(exchange.getRequestHeaders().getFirst("Authorization"));
      respond(exchange, 401, "unauthorized");
    });
    foreignServer.start();

    try {
      String domain = "http://localhost:" + fakeSalesforce.getAddress().getPort();
      OkHttpClient client = SalesforceOAuthClientSecret.authenticate(
          "test-client-id", "test-client-secret", domain);
      String foreignUrl = "http://localhost:" + foreignServer.getAddress().getPort() + "/foreign";

      try (Response response = client.newCall(
          new Request.Builder().url(foreignUrl).build()).execute()) {
        assertEquals(401, response.code());
      }

      assertNull(foreignAuthorizationHeader.get());
      assertEquals(0, tokenCount.get());
    } finally {
      foreignServer.stop(0);
      fakeSalesforce.stop(0);
    }
  }

  @Test
  void exposesClientCredentialsAuthenticationFailureWithoutRetryingTheApiCall() throws Exception {
    AtomicInteger apiRequestCount = new AtomicInteger();
    HttpServer fakeSalesforce = HttpServer.create(new InetSocketAddress("localhost", 0), 0);
    fakeSalesforce.createContext("/services/oauth2/token", exchange -> respond(
        exchange,
        400,
        "{\"error\":\"invalid_client\",\"error_description\":\"invalid client credentials\"}"));
    fakeSalesforce.createContext("/services/data", exchange -> {
      apiRequestCount.incrementAndGet();
      respond(exchange, 200, "ok");
    });
    fakeSalesforce.start();

    try {
      String domain = "http://localhost:" + fakeSalesforce.getAddress().getPort();
      OkHttpClient client = SalesforceOAuthClientSecret.authenticate(
          "test-client-id", "test-client-secret", domain);

      SalesforceAuthenticationException failure = assertThrows(
          SalesforceAuthenticationException.class,
          () -> client.newCall(
              new Request.Builder().url(domain + "/services/data").build()).execute());

      assertEquals(
          "Salesforce client credentials authentication failed: "
              + "{\"error\":\"invalid_client\","
              + "\"error_description\":\"invalid client credentials\"}",
          failure.getMessage());
      assertEquals(0, apiRequestCount.get());
    } finally {
      fakeSalesforce.stop(0);
    }
  }

  @Test
  void validatesCredentialsAndDomainBeforeBuildingTheClient() {
    assertEquals(
        "clientSecret must not be blank",
        assertThrows(
            IllegalArgumentException.class,
            () -> SalesforceOAuthClientSecret.authenticate("client-id", " ", "example.com"))
            .getMessage());
    assertEquals(
        "salesforceDomain must use HTTPS",
        assertThrows(
            IllegalArgumentException.class,
            () -> SalesforceOAuthClientSecret.authenticate(
                "client-id", "client-secret", "http://example.com"))
            .getMessage());
    assertEquals(
        "salesforceDomain must be the org's My Domain URL for client credentials flow",
        assertThrows(
            IllegalArgumentException.class,
            () -> SalesforceOAuthClientSecret.authenticate(
                "client-id", "client-secret", "https://login.salesforce.com"))
            .getMessage());
  }

  private static void respond(HttpExchange exchange, int status, String content) throws IOException {
    byte[] bytes = content.getBytes(StandardCharsets.UTF_8);
    exchange.sendResponseHeaders(status, bytes.length);
    try (var response = exchange.getResponseBody()) {
      response.write(bytes);
    }
  }
}
