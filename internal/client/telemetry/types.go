package telemetry

import "time"

// GraphQLResponse represents the structure of a GraphQL API response.
type GraphQLResponse struct {
	Data   GraphQLData    `json:"data"`
	Errors []GraphQLError `json:"errors,omitempty"`
}

// GraphQLError represents an error returned by the GraphQL API.
type GraphQLError struct {
	Message string `json:"message"`
}

// GraphQLData contains the data returned by the GraphQL API.
type GraphQLData struct {
	SignalsLatest OdometerResponse `json:"signalsLatest"`
}

// OdometerResponse contains the odometer-related data.
type OdometerResponse struct {
	LastSeen                                time.Time           `json:"lastSeen"`
	PowertrainTransmissionTravelledDistance OdometerMeasurement `json:"powertrainTransmissionTravelledDistance"`
}

// OdometerMeasurement represents an odometer reading with a timestamp.
type OdometerMeasurement struct {
	Timestamp time.Time `json:"timestamp"`
	Value     float64   `json:"value"`
}
