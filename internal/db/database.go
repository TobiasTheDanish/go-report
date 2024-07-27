package db

import (
	"database/sql"
	"errors"
	"fmt"
	"os"

	_ "github.com/tursodatabase/libsql-client-go/libsql"
)

type Owner struct {
	Id   int
	Name string
}

type Installation struct {
	Id      int
	OwnerId int
}

type DatabaseService interface {
	CreateOwner(ownerName string) (Owner, error)
	CreateOwnerIfNotExists(ownerName string) (Owner, error)
	ReadOwner(ownerName string) (Owner, error)
	CreateInstallation(ownerId int) (Installation, error)
	ReadInstallationsForOwner(ownerId int) ([]Installation, error)
	Close() error
}

type tursoService struct {
	db *sql.DB
}

func NewDatabaseService() (DatabaseService, error) {
	dbUrl := os.Getenv("TURSO_DATABASE_URL")
	dbToken := os.Getenv("TURSO_AUTH_TOKEN")

	connStr := fmt.Sprintf("%s?authToken=%s", dbUrl, dbToken)
	db, err := sql.Open("libsql", connStr)
	if err != nil {
		return nil, errors.Join(errors.New("Failed to open connection to db."), err)
	}

	return &tursoService{
		db: db,
	}, nil
}

func (s *tursoService) CreateOwnerIfNotExists(ownerName string) (Owner, error) {
	owner, err := s.ReadOwner(ownerName)
	if err != nil {
		return Owner{}, err
	}

	if owner.Id != -1 {
		return s.CreateOwner(ownerName)
	} else {
		return owner, nil
	}
}

func (s *tursoService) CreateOwner(ownerName string) (Owner, error) {
	res, err := s.db.Exec("INSERT INTO report_owners (name) VALUES (?)", ownerName)
	if err != nil {
		return Owner{}, err
	}

	id, err := res.LastInsertId()
	if err != nil {
		return Owner{}, err
	}

	return Owner{
		Id:   int(id),
		Name: ownerName,
	}, nil
}

func (s *tursoService) ReadOwner(ownerName string) (Owner, error) {
	rows, err := s.db.Query("SELECT * FROM report_owners WHERE name=?", ownerName)
	if err != nil {
		return Owner{}, err
	}
	defer rows.Close()

	for rows.Next() {
		var (
			id   int
			name string
		)
		if err := rows.Scan(&id, &name); err != nil {
			return Owner{}, err
		}
		return Owner{
			Id:   id,
			Name: name,
		}, nil
	}

	return Owner{Id: -1}, nil
}

func (s *tursoService) CreateInstallation(ownerId int) (Installation, error) {
	res, err := s.db.Exec("INSERT INTO report_installations (owner_id) VALUES (?)", ownerId)
	if err != nil {
		return Installation{}, err
	}

	id, err := res.LastInsertId()
	if err != nil {
		return Installation{}, err
	}

	return Installation{
		Id:      int(id),
		OwnerId: ownerId,
	}, nil
}

func (s *tursoService) ReadInstallationsForOwner(ownerId int) ([]Installation, error) {
	rows, err := s.db.Query("SELECT * FROM report_installations WHERE owner_id=?", ownerId)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	installations := make([]Installation, 0)
	for rows.Next() {
		var (
			id      int
			ownerId int
		)
		if err := rows.Scan(&id, &ownerId); err != nil {
			return nil, err
		}
		installations = append(installations, Installation{
			Id:      id,
			OwnerId: ownerId,
		})
	}

	return installations, nil
}

func (s *tursoService) Close() error {
	return s.db.Close()
}
