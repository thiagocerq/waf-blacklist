# Purge_IPs_Waf_Dynamodb_PROD” (Python 3.8).

# This Lambda is executing CloudWatch Event every 1 minute to purge table 
# (Cf_analyserequests_Waf_PROD) and remove expired IPs in (Cf_blocked_ips_Waf_PROD) and WAF Blacklist.

# Note: Timeout set to 30 seconds.

# - DYNAMODB_REGION: Region DynamoDB.
# - DYNAMODB_TABLE: Table with history of IPs with response errors.
# - DYNAMODB_TABLE_BLOCKED_IPS: Table with IPs blocked.
# - IP_SET_ID_AUTO_BLOCK: ID WAF Blacklist.
# - TIME_HISTORY_DYNAMODB: Logs greather equal X seconds are purged.
# - TIME_IP_BLOCKED_WAF: Time that IPs removed in (Cf_blocked_ips_Waf_PROD) and WAF Blacklist.


import boto3
import math
import time
import datetime
import ipaddress
from boto3.dynamodb.conditions import Key, Attr
from os import environ

# Get the service resource.
dynamodb = boto3.resource('dynamodb', region_name=environ['DYNAMODB_REGION'])
table = dynamodb.Table(environ['DYNAMODB_TABLE'])
table_blocked = dynamodb.Table(environ['DYNAMODB_TABLE_BLOCKED_IPS'])

# WAF
waf = boto3.client('waf')
API_CALL_NUM_RETRIES = 3

def valid_IPV4(ip):
    if ipaddress.ip_address(ip).version == 4:
        return True
    else:
        return False
        

def waf_get_ip_set(ip_set_id):
    response = None
    
    for attempt in range(API_CALL_NUM_RETRIES):
        try:
            response = waf.get_ip_set(IPSetId=ip_set_id)
        except Exception as e:
            print(e)
            delay = math.pow(2, attempt)
            print("[waf_get_ip_set] Retrying in %d seconds..." % (delay))
            time.sleep(delay)
        else:
            break
    else:
        print("[waf_get_ip_set] Failed ALL attempts to call API")

    return response
    
    
def waf_update_ip_set(ip_set_id, updates_list):
    response = None
    
    if updates_list != []:
        for attempt in range(API_CALL_NUM_RETRIES):
            try:
                response = waf.update_ip_set(IPSetId=ip_set_id,
                        ChangeToken=waf.get_change_token()['ChangeToken'],
                        Updates=updates_list)
                            
            except Exception as e:
                print(e)
                delay = math.pow(2, attempt)
                print("[waf_update_ip_set] Retrying in %d seconds..." % (delay))
                time.sleep(delay)
            else:
                break
        else:
            print("[waf_update_ip_set] Failed ALL attempts to call API")

    return response


def lambda_handler(event, context):
    IPS_REMOVE_WAF = []
    
    try:
        print('------ LIMPANDO TABELA DYNAMODB -------------')
        timestamp_removed_dynamodb=int(datetime.datetime.now().timestamp())-int(environ['TIME_HISTORY_DYNAMODB'])

        response = table.scan(
            IndexName='TIMESTAMP',
            FilterExpression=Attr('TIMESTAMP').lte(timestamp_removed_dynamodb)
        )
        
        count_removed_logs=len(response['Items'])
        
        print ('Excluindo %s logs antigos com mais de %s segundos do DYNAMODB.'%(count_removed_logs, str(environ['TIME_HISTORY_DYNAMODB'])))
        
        if count_removed_logs > 0:
            for k in response['Items']:
                table.delete_item(
                    Key={'ID': k['ID']}
                )
                
        print('------ LIMPANDO IPs DO WAF -------------')
        timestamp_removed_dynamodb=int(datetime.datetime.now().timestamp())-int(environ['TIME_IP_BLOCKED_WAF'])

        response = table_blocked.scan(
            IndexName='TIMESTAMP',
            FilterExpression=Attr('TIMESTAMP').lte(timestamp_removed_dynamodb)
        )
        
        count_removed_waf=len(response['Items'])
        
        if environ['IP_SET_ID_AUTO_BLOCK'] != None:
            response_waf = waf_get_ip_set(environ['IP_SET_ID_AUTO_BLOCK'])

            if response_waf != None:
                for k in response_waf['IPSet']['IPSetDescriptors']:
                    IPS_REMOVE_WAF.append(k['Value'].split('/')[0])

        if count_removed_waf > 0:
            print ('Excluindo %s IPs antigos com mais de %s segundos do WAF.'%(count_removed_waf, str(environ['TIME_IP_BLOCKED_WAF'])))
            
            for k in response['Items']:
                IP = k['IP']
                
                if IP in IPS_REMOVE_WAF:
                    if valid_IPV4(IP):
                        ip_type = 'IPV4'
                        mask = '32'
                    else:
                        ip_type = 'IPV6'
                        mask = '128'
                        
                    print('Deletando IP (%s/%s) do WAF!'%(IP,mask))
                    
                    JSON_IPS_REMOVE_WAF = [{
                        'Action': 'DELETE',
                        'IPSetDescriptor': {
                            'Type': ip_type,
                            'Value': "%s/%s"%(IP,mask)
                        }
                    }]
                    
                    try:
                        response = waf_update_ip_set(environ['IP_SET_ID_AUTO_BLOCK'], JSON_IPS_REMOVE_WAF)
                    except Exception as e:
                        print('Erro ao executar funcao de removocao de IP no WAF')
                        print(e)

                print('Deletando IP (%s) do DYNAMODB_BLOCK!'%(IP))
    
                table_blocked.delete_item(
                    Key={'IP': IP}
                )
        
    except Exception as e:
        print(e)