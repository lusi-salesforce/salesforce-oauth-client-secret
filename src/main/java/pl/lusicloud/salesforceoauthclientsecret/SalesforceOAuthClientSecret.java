package pl.lusicloud.salesforceoauthclientsecret;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.function.Supplier;

import okhttp3.Credentials;
import okhttp3.FormBody;
import okhttp3.HttpUrl;
import okhttp3.Interceptor;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

/**
 * Creates an OkHttp client authenticated with Salesforce's OAuth 2.0 client credentials flow.
 */
public final class SalesforceOAuthClientSecret {

  private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

  private SalesforceOAuthClientSecret() {
  }

  public static OkHttpClient authenticate(
      String clientId, String clientSecret, String salesforceDomain) {
    var externalClientApp = ExternalClientApp.from(clientId, clientSecret, salesforceDomain);
    Supplier<String> tokenProvider = new SalesforceClientCredentialsTokenProvider(externalClientApp);
    return new OkHttpClient.Builder()
        .addInterceptor(new LazyAuthenticationInterceptor(externalClientApp.domain(), tokenProvider))
        .build();
  }

  private static final class LazyAuthenticationInterceptor implements Interceptor {

    private final HttpUrl salesforceOrigin;
    private final Supplier<String> tokenProvider;
    private volatile TokenState tokenState = new TokenState(null);

    private LazyAuthenticationInterceptor(
        HttpUrl salesforceOrigin, Supplier<String> tokenProvider) {
      this.salesforceOrigin = salesforceOrigin;
      this.tokenProvider = tokenProvider;
    }

    @Override
    public Response intercept(Chain chain) throws IOException {
      var request = chain.request();
      if (!sameOrigin(request.url(), salesforceOrigin)) {
        return chain.proceed(request);
      }

      var requestToken = tokenState;
      if (requestToken.value() == null) {
        requestToken = reauthenticate(requestToken);
      }

      var response = chain.proceed(withAccessToken(request, requestToken.value()));
      if (response.code() == 401) {
        response.close();
        var newToken = reauthenticate(requestToken);
        return chain.proceed(withAccessToken(request, newToken.value()));
      }

      return response;
    }

    private synchronized TokenState reauthenticate(TokenState rejectedToken) {
      // A different request already replaced the snapshot that received the 401.
      if (tokenState != rejectedToken) {
        return tokenState;
      }

      tokenState = new TokenState(tokenProvider.get());
      return tokenState;
    }

    private Request withAccessToken(Request request, String token) {
      return request.newBuilder()
          .header("Authorization", "Bearer " + token)
          .build();
    }

    // Identity tracks refreshes even when Salesforce reissues the same token value.
    private record TokenState(String value) {
    }
  }

  private record ExternalClientApp(String clientId, String clientSecret, HttpUrl domain) {

    private static ExternalClientApp from(
        String clientId, String clientSecret, String salesforceDomain) {
      var configuredDomain = required(salesforceDomain, "salesforceDomain");
      var origin = HttpUrl.get(configuredDomain.contains("://")
          ? configuredDomain
          : "https://" + configuredDomain);
      var hasInvalidParts = !origin.username().isEmpty()
          || !origin.password().isEmpty()
          || origin.query() != null
          || origin.fragment() != null
          || !"/".equals(origin.encodedPath());
      if (hasInvalidParts) {
        throw new IllegalArgumentException("salesforceDomain must be a host name or origin URL");
      }

      var isLocalHttp = "http".equals(origin.scheme())
          && ("localhost".equals(origin.host()) || "127.0.0.1".equals(origin.host()));
      if (!origin.isHttps() && !isLocalHttp) {
        throw new IllegalArgumentException("salesforceDomain must use HTTPS");
      }
      if ("login.salesforce.com".equals(origin.host())
          || "test.salesforce.com".equals(origin.host())) {
        throw new IllegalArgumentException(
            "salesforceDomain must be the org's My Domain URL for client credentials flow");
      }

      return new ExternalClientApp(
          required(clientId, "clientId"),
          requiredSecret(clientSecret),
          origin);
    }

    private HttpUrl tokenEndpoint() {
      return domain.newBuilder()
          .addPathSegments("services/oauth2/token")
          .build();
    }
  }

  private static final class SalesforceClientCredentialsTokenProvider implements Supplier<String> {

    private final ExternalClientApp externalClientApp;
    private final OkHttpClient httpClient = new OkHttpClient();

    private SalesforceClientCredentialsTokenProvider(ExternalClientApp externalClientApp) {
      this.externalClientApp = externalClientApp;
    }

    @Override
    public String get() {
      var tokenRequest = new FormBody.Builder()
          .add("grant_type", "client_credentials")
          .build();
      var request = new Request.Builder()
          .url(externalClientApp.tokenEndpoint())
          .header("Authorization", Credentials.basic(
              externalClientApp.clientId(),
              externalClientApp.clientSecret(),
              StandardCharsets.UTF_8))
          .post(tokenRequest)
          .build();

      try (var response = httpClient.newCall(request).execute()) {
        var responseContent = response.body().string();
        if (!response.isSuccessful()) {
          throw new SalesforceAuthenticationException(
              "Salesforce client credentials authentication failed: " + responseContent);
        }
        return accessToken(responseContent);
      } catch (IOException failure) {
        throw new SalesforceAuthenticationException(
            "Could not request a Salesforce token: " + failure.getMessage());
      }
    }

    private String accessToken(String responseContent) {
      JsonNode responseBody;
      try {
        responseBody = OBJECT_MAPPER.readTree(responseContent);
      } catch (RuntimeException parsingFailure) {
        throw new SalesforceAuthenticationException(
            "Salesforce token response is not valid JSON");
      }
      if (responseBody == null) {
        throw new SalesforceAuthenticationException(
            "Salesforce token response is empty");
      }
      if (!responseBody.has("access_token")) {
        throw new SalesforceAuthenticationException(
            "Salesforce token response has no access_token");
      }
      var accessToken = responseBody.get("access_token").asString();
      if (accessToken == null || accessToken.isBlank()) {
        throw new SalesforceAuthenticationException(
            "Salesforce token response has a blank access_token");
      }
      return accessToken.trim();
    }
  }

  private static boolean sameOrigin(HttpUrl first, HttpUrl second) {
    return first.scheme().equals(second.scheme())
        && first.host().equals(second.host())
        && first.port() == second.port();
  }

  private static String required(String value, String name) {
    if (value == null || value.isBlank()) {
      throw new IllegalArgumentException(name + " must not be blank");
    }
    return value.trim();
  }

  private static String requiredSecret(String clientSecret) {
    if (clientSecret == null || clientSecret.isBlank()) {
      throw new IllegalArgumentException("clientSecret must not be blank");
    }
    return clientSecret;
  }
}
