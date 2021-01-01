package main

import (
	"context"
	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/zephiransas/go-authorizer/authorizer/token"
	"log"
	"strings"
)

func handleRequest(_ context.Context, event events.APIGatewayCustomAuthorizerRequest) (events.APIGatewayCustomAuthorizerResponse, error) {
	log.Println("Method ARN: " + event.MethodArn)

	tmp := strings.Split(event.MethodArn, ":")
	region := tmp[3]
	awsAccountID := tmp[4]
	apiGatewayArnTmp := strings.Split(tmp[5], "/")

	res := NewAuthorizeResponse("*", awsAccountID)

	res.Region = region
	res.APIID = apiGatewayArnTmp[0]
	res.Stage = apiGatewayArnTmp[1]

	r, err := token.Introspection(event.AuthorizationToken)
	if err != nil {
		log.Println(err)
		return events.APIGatewayCustomAuthorizerResponse{}, err
	}

	if r {
		res.addMethod(Allow, apiGatewayArnTmp[2], "*")
	} else {
		res.addMethod(Deny, apiGatewayArnTmp[2], "*")
	}
	return res.APIGatewayCustomAuthorizerResponse, nil
}

func main() {
	lambda.Start(handleRequest)
}

type Effect int

const (
	Allow Effect = iota
	Deny
)

func (e Effect) String() string {
	switch e {
	case Allow:
		return "Allow"
	case Deny:
		return "Deny"
	}
	return ""
}

type AuthorizeResponse struct {
	events.APIGatewayCustomAuthorizerResponse
	Region    string
	AccountID string
	APIID     string
	Stage     string
}

func NewAuthorizeResponse(principalID string, accountID string) *AuthorizeResponse {
	return &AuthorizeResponse{
		APIGatewayCustomAuthorizerResponse: events.APIGatewayCustomAuthorizerResponse{
			PrincipalID: principalID,
			PolicyDocument: events.APIGatewayCustomAuthorizerPolicy{
				Version: "2012-10-17",
			},
		},
		Region:    "*",
		AccountID: accountID,
		APIID:     "*",
		Stage:     "*",
	}
}

func (r *AuthorizeResponse) addMethod(effect Effect, verb string, resource string) {
	resourceArn := "arn:aws:execute-api:" +
		r.Region + ":" +
		r.AccountID + ":" +
		r.APIID + "/" +
		r.Stage + "/" +
		verb + "/" +
		strings.TrimLeft(resource, "/")

	s := events.IAMPolicyStatement{
		Effect:   effect.String(),
		Action:   []string{"execute-api:Invoke"},
		Resource: []string{resourceArn},
	}

	r.PolicyDocument.Statement = append(r.PolicyDocument.Statement, s)
}
