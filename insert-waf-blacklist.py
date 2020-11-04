# Insert_Waf_analyserequests_PROD” (Python 3.8).
# This Lambda is executing in Trigger DynamoDB (Cf_analyserequests_Waf_PROD) to analyse the IP registry has X counts in the last X seconds ago.
# We create this Lambda and DynamoDB (Cf_analyserequests_Waf_PROD) in region (sa-east-1).

# - COUNT_BLOCK: Quantity of IPs list in “TIME_CHECK_BLOCK” seconds ago.
# - DYNAMODB_REGION: Region DynamoDB.
# - DYNAMODB_TABLE: Table with history of IPs with response errors.
# - DYNAMODB_TABLE_BLOCKED_IPS: Table with IPs blocked.
# - IP_SET_ID_AUTO_BLOCK: ID WAF Blacklist.
# - TIME_CHECK_BLOCK: Time to analyse the last logs in table history.

import json
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


def check_ip_blocked_dynamodb(ip):
    response = None
    
    try:
        response = table_blocked.get_item(
            Key={
                'IP': ip
            }
        )
    except Exception as e:
        print(e)
        print("Erro ao consultar IP (%s) na tabela de IPs bloqueados"%ip)

    if len(response) > 1:
        return True
    else:
        return False
    
    
def insert_ip_blocked_dynamodb(ip):
    try:
        print("Inserindo IP (%s) na tabela de IPs bloqueados!" % (ip))
        datetime_blocked = datetime.datetime.now()
        timestamp_blocked = int(datetime_blocked.timestamp())
        
        response = table_blocked.put_item(
           Item={
                'IP': ip,
                'DATETIME': str(datetime_blocked),
                'TIMESTAMP': timestamp_blocked
            }
        )
    except Exception as e:
        print(e)
        print("Erro ao inserir IP (%s) na tabela de IPs bloqueados!" % (ip))
    

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
    

def waf_update_ip_set(ip_set_id, updates_list, ip_block):
    response = None
    
    if updates_list != []:
        for attempt in range(API_CALL_NUM_RETRIES):
            try:
                print("Inserindo IP (%s) na lista de bloqueios do WAF!" % (ip_block))
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
    JSON_IP_BLOCK = []
    
    for record in event['Records']:
        if record['eventName'] == 'INSERT':
            timestamp = record['dynamodb']['NewImage']['TIMESTAMP']['N']
            
            if valid_IPV4(record['dynamodb']['NewImage']['CLIENTIP']['S']):
                clientip = record['dynamodb']['NewImage']['CLIENTIP']['S']
            else:
                print("Formatando IPV6 (%s)" % (record['dynamodb']['NewImage']['CLIENTIP']['S']))
                clientip=str(ipaddress.ip_address(record['dynamodb']['NewImage']['CLIENTIP']['S']).exploded)
                
            timestamp_menos_time_block = int(timestamp) - int(environ['TIME_CHECK_BLOCK'])

            print('<------------------------->')
            print('Timestamp: ' + timestamp)
            print('Timestamp menos time: ' + str(timestamp_menos_time_block))
            print('ClientIP: ' + clientip)

            try:
                if not check_ip_blocked_dynamodb(clientip):
                    response = table.scan(
                        IndexName='CLIENTIPAndTIMESTAMP',
                        FilterExpression=Attr('TIMESTAMP').gte(timestamp_menos_time_block) & Attr('CLIENTIP').eq(clientip)
                    )
                    
                    count_items = len(response['Items'])
        
                    print('Quantidade de logs nos ultimos (' + str(environ['TIME_CHECK_BLOCK']) + 's): ' + str(count_items))
        
                    if count_items >= int(environ['COUNT_BLOCK']):
                        print('Verificando se IP (' + str(clientip) + ') ja consta na lista de bloqueio.')
                        exist_ip = False
                        
                        if check_ip_blocked_dynamodb(clientip):
                            exist_ip = True
                            print('IP (' + str(clientip) + ') ja consta na lista de bloqueio do DYNAMODB!')
                        else:  
                            # Double check. If not exist in DynamoDB, check list WAF
                            try:
                                if environ['IP_SET_ID_AUTO_BLOCK'] != None:
                                    response = waf_get_ip_set(environ['IP_SET_ID_AUTO_BLOCK'])
            
                                    if response != None:
                                        for k in response['IPSet']['IPSetDescriptors']:
                                            if k['Value'].split('/')[0] == clientip:
                                                exist_ip = True
                                                print('IP (' + str(clientip) + ') ja consta na lista de bloqueio WAF!')
                                                
                                                insert_ip_blocked_dynamodb(clientip)
                            except Exception as e:
                                print('Erro ao pegar lista de IPs ja bloqueados')
                                print(e)
                            
                        if not exist_ip: 
                            if valid_IPV4(clientip):
                                ip_type = 'IPV4'
                                mask = '32'
                                ip_block=clientip
                            else:
                                ip_type = 'IPV6'
                                mask = '128'
                                ip_block=clientip
                                
                            print('IP (' + str(ip_block) + ') sera bloqueado por ter (' + str(environ['COUNT_BLOCK']) + ') ou mais tentativas de erros nos ultimos (' + str(environ['TIME_CHECK_BLOCK']) + 's)')
                            JSON_IP_BLOCK.append({
                                'Action': 'INSERT',
                                'IPSetDescriptor': {
                                    'Type': ip_type,
                                    'Value': "%s/%s"%(ip_block,mask)
                                }
                            })
                            
                            try:
                                waf_update_ip_set(environ['IP_SET_ID_AUTO_BLOCK'], JSON_IP_BLOCK, ip_block)
                                insert_ip_blocked_dynamodb(ip_block)  
                            except Exception as e:
                                print('Erro ao executar funcao de insercao de IP no WAF')
                                print(e)
                  
                    print('>-------------------------<')   
                else:
                    print('IP (' + str(clientip) + ') ja consta na lista de bloqueio do DYNAMODB!')

            except Exception as e:
                print(e)