rule scheduled_task
{
    meta:
	author = "Cesar Diaz <cesar@cesardiaz.me>"
	description= "a scheduled task is created"

    strings:
	$s = "Microsoft.Win32.TaskScheduler"

        $t1 = "BootTrigger"
	$t2 = "LogonTrigger"
	$t3 = "DailyTrigger"
	$t4 = "TriggerCollection"
	$t5 = "TimeTrigger"

	$c1 = "TaskCreation"
	$c2 = "TaskLogonType"
	$c3 = "TaskFolder"
	$c4 = "TaskService"
	$c5 = "TaskDefinition"
	$c6 = "TaskRunLevel"
	$c7 = "TaskRegistrationInfo"
    
	condition:
		$s and 1 of ($c*) and 1 of ($t*)

}

