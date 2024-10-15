package indexer

// NoInscription represents the error when tehre isn't an inscription reveal transaction
// in the last block
type NoInscription struct {
	message string
}

func NewNoInscriptionError() NoInscription {
	return NoInscription{
		message: "No inscription in last block",
	}
}

func (ni NoInscription) Error() string {
	return ni.message
}
