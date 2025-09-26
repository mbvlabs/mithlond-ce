-- name: QueryUserByID :one
select * from users where id=?;

-- name: QueryUserByEmail :one
select * from users where email=?;

-- name: QueryUsers :many
select * from users;

-- name: QueryAllUsers :many
select * from users;

-- name: InsertUser :one
insert into
    users (id, created_at, updated_at, email, is_admin, password)
values
    (?, datetime('now'), datetime('now'), ?, ?, ?)
returning *;

-- name: UpdateUser :one
update users
    set updated_at=datetime('now'), email=?, is_admin=?, password=?
where id = ?
returning *;

-- name: DeleteUser :exec
delete from users where id=?;

-- name: QueryPaginatedUsers :many
select * from users 
order by created_at desc 
limit ? offset ?;

-- name: CountUsers :one
select count(*) from users;

