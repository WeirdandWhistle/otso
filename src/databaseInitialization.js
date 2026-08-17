export async function init(env) {
	await env.OTSO_DB.prepare(databaseInitString).bind().run(); 
}
export async function remove(env){
    await env.OTSO_DB.prepare(databaseDeleteString).bind().run();
}
const databaseDeleteString = `
DROP TABLE IF EXISTS Sessions;
DROP TABLE IF EXISTS OAuthTokens;
DROP TABLE IF EXISTS OAuthIssuers;
DROP TABLE IF EXISTS OAuthClients;
DROP TABLE IF EXISTS Users;
DROP TABLE IF EXISTS OIDCKeys;
DROP TABLE IF EXISTS KV;
`;

const databaseInitString = `
CREATE TABLE IF NOT EXISTS Users (
    userID TEXT NOT NULL PRIMARY KEY,
    authenticationMethods TEXT DEFAULT '',
    authorizedApps TEXT DEFAULT '',
    email TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    username TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS Sessions (
    sessionID TEXT NOT NULL PRIMARY KEY,
    sessionData TEXT,
    userID TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    FOREIGN KEY (userID) REFERENCES Users(userID)
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

CREATE TABLE IF NOT EXISTS OAuthClients (
    client_id TEXT NOT NULL PRIMARY KEY,
    client_secret_hash TEXT,
    redirection_URIs TEXT,
    client_type TEXT NOT NULL,
    name TEXT NOT NULL,
    ownerUserID TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    FOREIGN KEY (ownerUserID) REFERENCES Users(userID)
);

CREATE TABLE IF NOT EXISTS OAuthTokens (
    access_token TEXT NOT NULL PRIMARY KEY,
    expires BIGINT NOT NULL,
    scopes TEXT NOT NULL,
    refresh_token TEXT,
    userID TEXT NOT NULL,
    client_id TEXT  NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    FOREIGN KEY (userID) REFERENCES Users(userID),
    FOREIGN KEY (client_id) REFERENCES OAuthClients(client_id)
);

CREATE TABLE IF NOT EXISTS OIDCKeys (
    kid TEXT NOT NULL PRIMARY KEY,
    keypair TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL
);

CREATE TABLE IF NOT EXISTS KV (
    k TEXT NOT NULL PRIMARY KEY,
    v TEXT,
    ttl BIGINT
);
`;
