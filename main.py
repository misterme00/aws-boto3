import boto3
import datetime
import json


cloudtrail = boto3.client('cloudtrail')
#ec2 = boto3.resource('ec2')
ec2 = boto3.resource('ec2')
#iid = 'i-0fecd1ee86f6aa449'
iid = 'i-0d63b207e435dc1b2'
instance = ec2.Instance(iid)
print(instance.launch_time)

#id = instance.instance


#endtime = datetime.datetime.now()
#endtime = instance.launch_time + interval + interval

interval = datetime.timedelta(minutes=30)
starttime = instance.launch_time - interval
endtime = instance.launch_time + interval 
print(starttime)
print(endtime)


#i-0d63b207e435dc1b2

def get_events(instanceid):

    try:
        response = cloudtrail.lookup_events(
            LookupAttributes=[
                {
                    'AttributeKey': 'ResourceName',
                    'AttributeValue': instanceid
                },
            ],
            StartTime=starttime,
            EndTime=endtime,
            MaxResults=50
        )
    except Exception as e:
        print(e)
        print('Unable to retrieve CloudTrail events for user "{}"'.format(instanceid))
        raise(e)
    return response



events = get_events(instance.instance_id)
for event in events['Events']:
        username = event.get("Username")
        ct_event = event.get("CloudTrailEvent")
        event_name = event.get("EventName")
        event_time = event.get("EventTime")
        print("{0} - {1} - {2} - {3}".format(username,ct_event,event_name,event_time))

#print(response)
#events = json.dumps(response)
#print(events)