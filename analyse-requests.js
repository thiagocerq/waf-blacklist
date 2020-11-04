// This Lambda is executing in Origin Response CloudFront. 
// Used to capture Response Errors and record them in DynamoDB (Cf_analyserequests_Waf_PROD).

// Note: Alter the “region” and “endPointAnalyse” according to your need. 
// The Region is in “sa-east-1” because it’s is the same region DynamoDB and the region where We has more traffic on our website. 
// But we create this Lambda in “us-east-1”.

// Permission this Lambda are “CloudWatch”, “CloudWatch Logs”, “WAF” and ‘DynamoDB”.

'use strict';

var http = require('http');

// Load the SDK for JavaScript
const https = require('https');
var AWS = require('aws-sdk');

// Set the region 
AWS.config.update({region: 'sa-east-1'}); 

// Create the DynamoDB service object
var ddb = new AWS.DynamoDB({
  region: "sa-east-1",
  httpOptions: {
    agent: new https.Agent({
      rejectUnauthorized: true,
      keepAlive: true
    })
  }
});

// Search in array
function isInArray(array, search)
{
    return array.indexOf(search) >= 0;
}

exports.handler = (event, context, callback) => {
    const response = event.Records[0].cf.response;
    const request = event.Records[0].cf.request;
    
    // EndPoints (request.uri) analysis and insert in DynamoDB
    var endPointsAnalyse = ['/login','/test','/healthcheck'];
    var blockErrorCodes = ['400','401'];

    if (isInArray(blockErrorCodes, response.status)) {
        if(isInArray(endPointsAnalyse, request.uri.replace(/\/$/, ""))){
            // Date and Time
            var d = new Date()
            var timestamp_seconds = Math.floor(d.getTime() / 1000)

            // Prepare datas to be sent to DDB
            var params = {
              TableName: 'Cf_analyserequests_Waf_PROD',
              Item: {
                'ID': {S: d.getTime().toString()+request.clientIp},
                'CLIENTIP' : {S: request.clientIp},
                'HTTPCODE' : {N: response.status},
                'ENDPOINT' : {S: request.uri},
                'DATETIME' : {S: d.toString()},
                'TIMESTAMP' : {N: timestamp_seconds.toString()},
              }
            };
            
            // Call DynamoDB to add the item to the table
            ddb.putItem(params, function(err, data) {
              if (err) {
                console.log("Error", err);
              } else {
                console.log("Success", data);
              }
            });
        }
    }

    callback(null, response);

};