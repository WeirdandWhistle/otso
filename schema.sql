DROP TABLE IF EXISTS Sessions;
DROP TABLE IF EXISTS OAuthTokens;
DROP TABLE IF EXISTS OAuthIssuers;
DROP TABLE IF EXISTS OAuthClients;
DROP TABLE IF EXISTS Users;
CREATE TABLE IF NOT EXISTS Users (
    userID TEXT NOT NULL PRIMARY KEY,
    authenticationMethods TEXT DEFAULT '',
    authorizedApps TEXT DEFAULT '',
    email TEXT,
    username TEXT NOT NULL
);
INSERT INTO Users (userID, username) VALUES ('userid', 'username');

DROP TABLE IF EXISTS Sessions;
CREATE TABLE IF NOT EXISTS Sessions (
    sessionID TEXT NOT NULL PRIMARY KEY,
    sessionData TEXT,
    userID TEXT NOT NULL,
    FOREIGN KEY (userID) REFERENCES Users(userID)
);
INSERT INTO Sessions (userID, sessionID) VALUES ('userid', 's');

DROP TABLE IF EXISTS OAuthState;
-- CREATE TABLE IF NOT EXISTS OAuthState ( -- not needed
--     stateID TEXT PRIMARY KEY,
--     stateData TEXT
-- );

DROP TABLE IF EXISTS OAuthIssuers;
CREATE TABLE IF NOT EXISTS OAuthIssuers (
    ID TEXT NOT NULL PRIMARY KEY,
    issuer TEXT NOT NULL,
    username TEXT,
    email TEXT,
    access_token TEXT,
    refresh_token TEXT,
    userID TEXT NOT NULL,
    FOREIGN KEY (userID) REFERENCES Users(userID)
);

-- OAuth provider (Otso) tables (eg.. clients, access_token, etc...)
DROP TABLE IF EXISTS OAuthClients;
CREATE TABLE IF NOT EXISTS OAuthClients (
    client_id TEXT NOT NULL PRIMARY KEY,
    client_secret_hash TEXT,
    redirection_URIs TEXT,
    client_type TEXT NOT NULL,
    name TEXT NOT NULL,
    ownerUserID TEXT NOT NULL,
    FOREIGN KEY (ownerUserID) REFERENCES Users(userID)
);
INSERT INTO OAuthClients (ownerUserID, client_id, client_type, name) VALUES ('userid', 'client_id', 'public', 'app');

DROP TABLE IF EXISTS OAuthTokens;
CREATE TABLE IF NOT EXISTS OAuthTokens (
    access_token TEXT NOT NULL PRIMARY KEY,
    expires BIGINT NOT NULL,
    scopes TEXT NOT NULL,
    refresh_token TEXT,
    userID TEXT NOT NULL,
    client_id TEXT  NOT NULL,
    FOREIGN KEY (userID) REFERENCES Users(userID),
    FOREIGN KEY (client_id) REFERENCES OAuthClients(client_id)
);
