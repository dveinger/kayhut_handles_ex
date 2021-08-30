# kayhut_handles_ex

## Background

The perpose of the exercise is to find and print for a given process (by name/id) all it's handles.


## Solution Description

To find the process handles:
- Retrieve a list with all current system processes.
- Find the processes that have a matching id/name as the given argument, and save their name and pid. Note- if there's a process with id X, and another process with name X, the program shows them both.
- Retrieve a list of all current system handles.
- For each process, find the handles that belong to it by comparing pid.
- For each handle, retrieve it's object, and the object's name, pointer count and handle count.
- print the results.

## Remarks

- I've used winapi's various methods to retrieve the system information.
- Large part of the information is not documented in microsoft's docs (mainly about handling handles), so I've used different articles and solutions about the topic. I'm adding the links to the main articles that i've used.
- Almost everything of what I did is new for me, so I've learned alot from this exercise :)

## Links

- About getting the process list:
https://docs.microsoft.com/en-us/windows/win32/psapi/enumerating-all-processes

- Solutions to enumerating handles in c and c++:
https://github.com/SinaKarvandi/Process-Magics/blob/master/EnumAllHandles/EnumAllHandles/EnumAllHandles.cpp
http://www.cplusplus.com/forum/windows/95774/

- Artice about NtQueryObject method, which doesn't work as expected:
https://www.vbforums.com/showthread.php?859341-How-to-Use-NtQueryObject-function-with-ObjectAllTypesInformation
