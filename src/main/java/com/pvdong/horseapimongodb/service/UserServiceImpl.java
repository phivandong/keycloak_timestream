package com.pvdong.horseapimongodb.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.pvdong.horseapimongodb.config.KeycloakProvider;
import com.pvdong.horseapimongodb.dto.*;
import com.pvdong.horseapimongodb.entity.User;
import com.pvdong.horseapimongodb.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.apache.hc.client5.http.classic.methods.HttpGet;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.keycloak.KeycloakPrincipal;
import org.keycloak.KeycloakSecurityContext;
import org.keycloak.adapters.springsecurity.token.KeycloakAuthenticationToken;
import org.keycloak.admin.client.CreatedResponseUtil;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.admin.client.resource.UserResource;
import org.keycloak.admin.client.resource.UsersResource;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.AccessTokenResponse;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.RoleRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.core.client.config.ClientOverrideConfiguration;
import software.amazon.awssdk.core.retry.RetryPolicy;
import software.amazon.awssdk.http.apache.ApacheHttpClient;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.timestreamquery.TimestreamQueryClient;
import software.amazon.awssdk.services.timestreamquery.model.*;
import software.amazon.awssdk.services.timestreamquery.paginators.QueryIterable;
import software.amazon.awssdk.services.timestreamwrite.TimestreamWriteClient;
import software.amazon.awssdk.services.timestreamwrite.model.*;
import software.amazon.awssdk.services.timestreamwrite.model.MeasureValueType;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.core.Response;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.Principal;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {
    private final UserRepository userRepository;
    private final KeycloakProvider keycloakProvider;
    private final RestTemplate restTemplate;

    @Override
    public User findUserById(String id) {
        return userRepository.findById(id).orElseThrow(() -> new RuntimeException("User not found"));
    }

    @Override
    public User registration(SignupRequest signupRequest) {
        RealmResource realmResource = keycloakProvider.getInstance().realm(keycloakProvider.realm);
        UsersResource usersResource = realmResource.users();
        CredentialRepresentation credentialRepresentation = createPasswordCredentials(signupRequest.getPassword());

        ClientRepresentation client = realmResource.clients().findByClientId(keycloakProvider.clientID).get(0);

        UserRepresentation keycloakUser = new UserRepresentation();
        keycloakUser.setUsername(signupRequest.getUsername());
        keycloakUser.setCredentials(Collections.singletonList(credentialRepresentation));
        keycloakUser.setEmail(signupRequest.getEmail());
        keycloakUser.setEnabled(true);
        keycloakUser.setEmailVerified(true);

        Response response = usersResource.create(keycloakUser);

        String userId = CreatedResponseUtil.getCreatedId(response);
        UserResource userResource = usersResource.get(userId);

        List<RoleRepresentation> rolesOfUser = userResource.roles().clientLevel(client.getId()).listAll();
        rolesOfUser.add(realmResource.clients().get(client.getId()).roles().get(signupRequest.getRole()).toRepresentation());
        userResource.roles().clientLevel(client.getId()).add(rolesOfUser);

        if (response.getStatus() == 201) {
            User localUser = new User();
            localUser.setUsername(signupRequest.getUsername());
            localUser.setPassword(signupRequest.getPassword());
            localUser.setEmail(signupRequest.getEmail());
            localUser.setRoles(Collections.singletonList(signupRequest.getRole()));
            User savedUser = userRepository.save(localUser);
            writeRecords("registration", savedUser.getId(), signupRequest.getUsername(), signupRequest.getRole());
            return savedUser;
        } else {
            throw new RuntimeException("Error");
        }
    }

    @Override
    public User changePassword(ChangePasswordRequest changePasswordRequest) {
        RealmResource realmResource = keycloakProvider.getInstance().realm(keycloakProvider.realm);
        UserResource userResource = realmResource.users().get(getCurrentUserId());
        CredentialRepresentation credentialRepresentation = createPasswordCredentials(changePasswordRequest.getNewPassword());

        UserRepresentation keycloakUser = userResource.toRepresentation();
        keycloakUser.setCredentials(Collections.singletonList(credentialRepresentation));

        userResource.update(keycloakUser);

        User localUser = userRepository.findByUsername(getCurrentUsername());
        localUser.setPassword(changePasswordRequest.getNewPassword());
        writeRecords("change password", localUser.getId(), getCurrentUsername(), localUser.getRoles().get(0));
        return userRepository.save(localUser);
    }

    @Override
    public void deleteUser(String id) {
        RealmResource realmResource = keycloakProvider.getInstance().realm(keycloakProvider.realm);
        UserRepresentation keycloakUser = realmResource.users().search(findUserById(id).getUsername()).get(0);
        realmResource.users().get(keycloakUser.getId()).remove();
        writeRecords("delete user", id, getCurrentUsername(), findUserById(id).getRoles().get(0));
        userRepository.deleteById(id);
    }

    @Override
    public AccessTokenResponse login(LoginRequest loginRequest) {
        Keycloak keycloak = keycloakProvider.newKeycloakBuilderWithPasswordCredentials(loginRequest.getUsername(), loginRequest.getPassword()).build();
        writeRecords("login", userRepository.findByUsername(loginRequest.getUsername()).getId(), loginRequest.getUsername(), userRepository.findByUsername(loginRequest.getUsername()).getRoles().get(0));
        return keycloak.tokenManager().getAccessToken();
    }

    @Override
    public void logout(String refreshToken) {
        MultiValueMap<String, String> requestParams = new LinkedMultiValueMap<>();
        requestParams.add("client_id", keycloakProvider.clientID);
        requestParams.add("client_secret", keycloakProvider.clientSecret);
        requestParams.add("refresh_token", refreshToken);
        logoutUserSession(requestParams);
    }

    private void logoutUserSession(MultiValueMap<String, String> requestParams) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(requestParams, headers);
        String url = "http://localhost:8181/realms/horse-api/protocol/openid-connect/logout";
        restTemplate.postForEntity(url, request, Object.class);
    }

    @Override
    public List<ActivityResponse> getUserActivity() {
        String userId = userRepository.findByUsername(getCurrentUsername()).getId();
        String QUERY = "SELECT * FROM \"user_activity_db\".\"user_activity_logs\" WHERE userId = '" + userId + "' ORDER BY time DESC";
        return runQuery(QUERY);
    }

    @Override
    public User registerUser(String role) throws IOException {
        ObjectMapper objectMapper = new ObjectMapper();
        KeycloakAuthenticationToken authentication = (KeycloakAuthenticationToken) SecurityContextHolder.getContext().getAuthentication();
        KeycloakPrincipal principal = (KeycloakPrincipal) authentication.getPrincipal();
        String accessToken = principal.getKeycloakSecurityContext().getTokenString();

        RealmResource realmResource = keycloakProvider.getInstance().realm(keycloakProvider.realm);
        UserResource userResource = realmResource.users().get(getCurrentUserId());
        ClientRepresentation kcClient = realmResource.clients().findByClientId(keycloakProvider.clientID).get(0);

        List<RoleRepresentation> rolesOfUser = userResource.roles().clientLevel(kcClient.getId()).listAll();
        rolesOfUser.add(realmResource.clients().get(kcClient.getId()).roles().get(role).toRepresentation());
        userResource.roles().clientLevel(kcClient.getId()).add(rolesOfUser);

        try (CloseableHttpClient client = HttpClients.createDefault()) {
            HttpGet request = new HttpGet("http://localhost:8181/realms/horse-api/protocol/openid-connect/userinfo");
            request.setHeader("Authorization", String.format("Bearer %s", accessToken));
            UserInfoDto userInfoDto = client.execute(request, httpResponse -> objectMapper.readValue(httpResponse.getEntity().getContent(), UserInfoDto.class));

            User user = new User();
            user.setEmail(userInfoDto.getEmail());
            user.setUsername(userInfoDto.getEmail());
            user.setRoles(Collections.singletonList(role));

            User savedUser = userRepository.save(user);
            writeRecords("social-register", savedUser.getId(), savedUser.getUsername(), savedUser.getRoles().get(0));
            return savedUser;
        }
    }

    @Override
    public String googleLogin(HttpServletRequest request) {
        try {
//            return getFinalURL("http://localhost:8080/api/user/activity-history") + "&kc_idp_hint=google";
            return getFinalURL(getFinalURL("http://localhost:8080/api/user/activity-history") + "&kc_idp_hint=google");
//            return getFinalURL(getURLValue(request)) + "&kc_idp_hint=google";
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }

    @Override
    public String facebookLogin(HttpServletRequest request) {
        try {
//            return getFinalURL("http://localhost:8080/api/user/activity-history") + "&kc_idp_hint=facebook";
            return getFinalURL(getURLValue(request)) + "&kc_idp_hint=facebook";
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }

    private static String getFinalURL(String url) throws IOException {
        HttpURLConnection con = (HttpURLConnection) new URL(url).openConnection();
        con.setInstanceFollowRedirects(false);
        con.connect();
        con.getInputStream();

        if (con.getResponseCode() == HttpURLConnection.HTTP_MOVED_PERM || con.getResponseCode() == HttpURLConnection.HTTP_MOVED_TEMP) {
            String redirectUrl = con.getHeaderField("Location");
            return getFinalURL(redirectUrl);
        }
        return url;
    }

    private String getURLValue(HttpServletRequest request) {
        return request.getRequestURI();
    }

    private static CredentialRepresentation createPasswordCredentials(String password) {
        CredentialRepresentation passwordCredentials = new CredentialRepresentation();
        passwordCredentials.setTemporary(false);
        passwordCredentials.setType(CredentialRepresentation.PASSWORD);
        passwordCredentials.setValue(password);
        return passwordCredentials;
    }

    private String getCurrentUsername() {
        KeycloakAuthenticationToken authentication = (KeycloakAuthenticationToken) SecurityContextHolder.getContext().getAuthentication();
        Principal principal = (Principal) authentication.getPrincipal();
        if (principal instanceof KeycloakPrincipal) {
            return principal.getName();
        } else {
            throw new RuntimeException("No user");
        }
    }

    private String getCurrentUserId() {
        KeycloakAuthenticationToken authentication = (KeycloakAuthenticationToken) SecurityContextHolder.getContext().getAuthentication();
        KeycloakPrincipal principal = (KeycloakPrincipal) authentication.getPrincipal();
        KeycloakSecurityContext session = principal.getKeycloakSecurityContext();
        AccessToken accessToken = session.getToken();
        return accessToken.getSubject();
    }

    private void writeRecords(String activity_name, String userId, String username, String role) {
        TimestreamWriteClient timestreamWriteClient = buildWriteClient();
        List<Record> records = new ArrayList<>();
        final long time = System.currentTimeMillis();

        List<Dimension> dimensions = new ArrayList<>();

        final Dimension region = Dimension.builder().name("region").value("ap-southeast-2").build();

        dimensions.add(region);

        Record activityLog = Record.builder()
                .dimensions(dimensions)
                .measureValueType(MeasureValueType.MULTI)
                .measureName("activity-record")
                .measureValues(
                        MeasureValue.builder().name("userId").value(userId).type(MeasureValueType.VARCHAR).build(),
                        MeasureValue.builder().name("user").value(username).type(MeasureValueType.VARCHAR).build(),
                        MeasureValue.builder().name("activity").value(activity_name).type(MeasureValueType.VARCHAR).build(),
                        MeasureValue.builder().name("role").value(role).type(MeasureValueType.VARCHAR).build()
                )
                .time(String.valueOf(time))
                .build();

        records.add(activityLog);
        WriteRecordsRequest writeRecordsRequest = WriteRecordsRequest.builder().databaseName("user_activity_db").tableName("user_activity_logs").records(records).build();

        try {
            WriteRecordsResponse writeRecordsResponse = timestreamWriteClient.writeRecords(writeRecordsRequest);
            System.out.println("WriteRecords Status: " + writeRecordsResponse.sdkHttpResponse().statusCode());
        } catch (RejectedRecordsException e) {
            System.out.println("RejectedRecords: " + e);
            for (RejectedRecord rejectedRecord : e.rejectedRecords()) {
                System.out.println("Rejected Index " + rejectedRecord.recordIndex() + ": " + rejectedRecord.reason());
            }
            System.out.println("Other records were written successfully.");
        } catch (Exception e) {
            System.out.println("Error: " + e);
        }
    }

    private static TimestreamWriteClient buildWriteClient() {
        AwsBasicCredentials credentials = AwsBasicCredentials.create("access_key_id", "secret_access_key");
        StaticCredentialsProvider credentialsProvider = StaticCredentialsProvider.create(credentials);

        ApacheHttpClient.Builder httpClientBuilder = ApacheHttpClient.builder();
        httpClientBuilder.maxConnections(5000);

        RetryPolicy.Builder retryPolicy = RetryPolicy.builder();
        retryPolicy.numRetries(10);

        ClientOverrideConfiguration.Builder overrideConfig = ClientOverrideConfiguration.builder();
        overrideConfig.apiCallAttemptTimeout(Duration.ofSeconds(20));
        overrideConfig.retryPolicy(retryPolicy.build());

        return TimestreamWriteClient.builder()
                .credentialsProvider(credentialsProvider)
                .httpClientBuilder(httpClientBuilder)
                .overrideConfiguration(overrideConfig.build())
                .region(Region.of("ap-southeast-2"))
                .build();
    }

    private List<ActivityResponse> runQuery(String queryString) {
        TimestreamQueryClient timestreamQueryClient = buildQueryClient();
        List<ActivityResponse> activityLogs = new ArrayList<>();

        try {
            QueryRequest queryRequest = QueryRequest.builder().queryString(queryString).build();
            final QueryIterable queryResponseIterator = timestreamQueryClient.queryPaginator(queryRequest);
            for (QueryResponse queryResponse : queryResponseIterator) {
                activityLogs.addAll(parseQueryResult(queryResponse));
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return activityLogs;
    }

    private List<ActivityResponse> parseQueryResult(QueryResponse response) {
        List<ActivityResponse> logs = new ArrayList<>();
        List<ColumnInfo> columnInfo = response.columnInfo();
        List<Row> rows = response.rows();
        for (Row row : rows) {
            String[] data = parseRow(columnInfo, row).split(",");
            ActivityResponse activityResponse = new ActivityResponse();
            activityResponse.setUserId(data[5]);
            activityResponse.setUserName(data[6]);
            activityResponse.setActivityName(data[4]);
            activityResponse.setRole(data[3]);
            activityResponse.setTime(data[2]);
            logs.add(activityResponse);
        }
        return logs;
    }

    private String parseRow(List<ColumnInfo> columnInfo, Row row) {
        List<Datum> data = row.data();
        List<String> rowOutput = new ArrayList<>();
        // iterate every column per row
        for (int j = 0; j < data.size(); j++) {
            ColumnInfo info = columnInfo.get(j);
            Datum datum = data.get(j);
            rowOutput.add(parseDatum(info, datum));
        }
        return String.format("%s", rowOutput.stream().map(Object::toString).collect(Collectors.joining(",")));
    }

    private String parseDatum(ColumnInfo info, Datum datum) {
        if (datum.nullValue() != null && datum.nullValue()) {
            return info.name() + "=" + "NULL";
        }
        Type columnType = info.type();
        // If the column is of TimeSeries Type
        if (columnType.timeSeriesMeasureValueColumnInfo() != null) {
            return parseTimeSeries(info, datum);
        }
        // If the column is of Array Type
        else if (columnType.arrayColumnInfo() != null) {
            List<Datum> arrayValues = datum.arrayValue();
            return info.name() + "=" + parseArray(info.type().arrayColumnInfo(), arrayValues);
        }
        // If the column is of Row Type
        else if (columnType.rowColumnInfo() != null && columnType.rowColumnInfo().size() > 0) {
            List<ColumnInfo> rowColumnInfo = info.type().rowColumnInfo();
            Row rowValues = datum.rowValue();
            return parseRow(rowColumnInfo, rowValues);
        }
        // If the column is of Scalar Type
        else {
            return datum.scalarValue();
        }
    }

    private String parseTimeSeries(ColumnInfo info, Datum datum) {
        List<String> timeSeriesOutput = new ArrayList<>();
        for (TimeSeriesDataPoint dataPoint : datum.timeSeriesValue()) {
            timeSeriesOutput.add("{time=" + dataPoint.time() + ", value=" +
                    parseDatum(info.type().timeSeriesMeasureValueColumnInfo(), dataPoint.value()) + "}");
        }
        return String.format("[%s]", timeSeriesOutput.stream().map(Object::toString).collect(Collectors.joining(",")));
    }

    private String parseArray(ColumnInfo arrayColumnInfo, List<Datum> arrayValues) {
        List<String> arrayOutput = new ArrayList<>();
        for (Datum datum : arrayValues) {
            arrayOutput.add(parseDatum(arrayColumnInfo, datum));
        }
        return String.format("[%s]", arrayOutput.stream().map(Object::toString).collect(Collectors.joining(",")));
    }

    private static TimestreamQueryClient buildQueryClient() {
        AwsBasicCredentials credentials = AwsBasicCredentials.create("access_key_id", "secret_access_key");
        StaticCredentialsProvider credentialsProvider = StaticCredentialsProvider.create(credentials);

        return TimestreamQueryClient.builder()
                .credentialsProvider(credentialsProvider)
                .region(Region.of("ap-southeast-2"))
                .build();
    }
}
