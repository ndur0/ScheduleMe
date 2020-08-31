# ScheduleMe  (C#)
Credit - - - > http://remoteawesomethoughts.blogspot.com/2019/05/windows-10-task-schedulerservice.html

The ScheduleMe project plays a part in establishing persistence via the WptsExtensions.dll DLL hijack.

ScheduleMe allows the operator to check the users PATH variable for writeable directories to drop the hijackable, malicious dll (see my WindowsCoreDeviceInfo project for a dll to drop).  

Option to restart the computer, assuming the user is NOT an admin for the local machine.  A restart is required to trigger the Task Scheduler unless you have NT_AUTHORITY\SYSTEM rights (in that case 'net stop/start schedule').

** when I get some time I will pull together the tasks (ie: include/upload dll, restart, etc) into a .cna to use with Cobalt Strike.  In the meantime, enough there to do the rest manually.
