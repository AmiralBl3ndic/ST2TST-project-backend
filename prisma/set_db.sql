DROP TABLE IF EXISTS Users;
DROP TABLE IF EXISTS AuthorizedEmails;

CREATE TABLE AuthorizedEmails(
    "id" INTEGER PRIMARY KEY AUTOINCREMENT,
    "email" TEXT UNIQUE NOT NULL,
    "role" TEXT NOT NULL
);

CREATE TABLE Users(
    "id" INTEGER PRIMARY KEY AUTOINCREMENT,
    "email" TEXT UNIQUE NOT NULL,
    "password" TEXT,
    "role" TEXT NOT NULL
);

INSERT INTO AuthorizedEmails(email, role) VALUES ('st2tst_admin@efrei.net', 'ADMIN');
