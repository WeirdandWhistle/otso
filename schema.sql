CREATE TABLE IF NOT EXISTS Users (
    userID TEXT NOT NULL PRIMARY KEY,
    authenticationMethods TEXT,
    email TEXT,
    username TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS Sessions (
    sessionID TEXT NOT NULL PRIMARY KEY,
    stateData TEXT,
    userID TEXT NOT NULL,
    FOREIGN KEY (userID) REFERENCES Users(userID)
);

CREATE TABLE IF NOT EXISTS UserCreationState (
    stateID TEXT NOT NULL PRIMARY KEY,
    stateData TEXT
);

CREATE TABLE IF NOT EXISTS OAuthState (
    stateID TEXT PRIMARY KEY,
    stateData TEXT
);

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
