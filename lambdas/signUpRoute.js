import { CognitoIdentityProviderClient, SignUpCommand } from "@aws-sdk/client-cognito-identity-provider";
import { createHmac } from 'crypto';
const client = new CognitoIdentityProviderClient({
  region: 'us-east-1'
});

export const handler = async (event) => {
  const { birthdate, username, password, email, firstName, lastName, gender, zoneinfo } = JSON.parse(event.body);
  const cognitoClientId = event.stageVariables.COGNITO_CLIENT_ID || process.env.COGNITO_CLIENT_ID;
  const cognitoClientSecret = event.stageVariables.COGNITO_CLIENT_SECRET || process.env.COGNITO_CLIENT_SECRET;
  
  const response = {
    isBase64Encoded: false,
    headers: {
      "content-type": "application/json"
    }
  };
  
  if (!username || !email || !birthdate || !firstName || !lastName) {
    response.statusCode = 400;
    response.body = JSON.stringify({
      message: "Bad request, 1 or more required fields are missing"
    });
    return response;
  }
  
  const hasher = createHmac('sha256', cognitoClientSecret);
  hasher.update(`${username}${cognitoClientId}`);
  const secretHash = hasher.digest('base64');
  
  const input = {
    ClientId: cognitoClientId,
    SecretHash: secretHash,
    Username: username,
    Password: password,
    UserAttributes: [
      {
        Name: "email",
        Value: email,
      },
      {
        Name: "birthdate",
        Value: birthdate,
      },
      {
        Name: "family_name",
        Value: lastName,
      },
      {
        Name: "given_name",
        Value: firstName,
      },
      {
        Name: "gender",
        Value: gender || null,
      },
      {
        Name: "zoneinfo",
        Value: zoneinfo || null,
      }
    ]
  };

  const command = new SignUpCommand(input);
  try {
    const cognitoResponse = await client.send(command);
    response.statusCode = 200;
    response.body = JSON.stringify({
      id: cognitoResponse.UserSub,
    });
  } catch (e) {
    console.error(e);
    response.statusCode = 500;
    response.body = JSON.stringify({
      message: e.message
    });
  }

  return response;
};