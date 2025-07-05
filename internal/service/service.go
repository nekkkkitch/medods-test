package service

type Service struct {
	db DB
	j  JWT
}

func New(db DB, j JWT) (*Service, error) {
	return &Service{db: db, j: j}, nil
}
