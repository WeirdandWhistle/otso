DROP TABLE IF EXISTS Users;
CREATE TABLE IF NOT EXISTS Users (
    userID TEXT NOT NULL PRIMARY KEY,
    authenticationMethods TEXT,
    authorizedApps TEXT,
    email TEXT,
    username TEXT NOT NULL
);

DROP TABLE IF EXISTS Sessions;
CREATE TABLE IF NOT EXISTS Sessions (
    sessionID TEXT NOT NULL PRIMARY KEY,
    stateData TEXT,
    userID TEXT NOT NULL,
    FOREIGN KEY (userID) REFERENCES Users(userID)
);

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
CREATE TABLE IF NOT EXISTS OAuthClients (
    client_id TEXT NOT NULL PRIMARY KEY,
    client_secret_hash TEXT,
    redirection_URIs TEXT,
    client_type TEXT NOT NULL,
    name TEXT NOT NULL,
    ownerUserID TEXT NOT NULL,
    FOREIGN KEY (ownerUserID) REFERENCES Users(userID)
);
