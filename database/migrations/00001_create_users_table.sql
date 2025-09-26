-- +goose Up
-- +goose StatementBegin
SELECT 'up SQL query';
create table users (
    id TEXT NOT NULL PRIMARY KEY,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL,

    email VARCHAR(255) UNIQUE NOT NULL,
    is_admin INTEGER NOT NULL DEFAULT 0,
    password BLOB NOT NULL
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
SELECT 'down SQL query';
drop table users;
-- +goose StatementEnd
