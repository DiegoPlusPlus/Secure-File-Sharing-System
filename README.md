# Secure-File-Sharing-System

Provided some cryptographic library functions, I used them to design a secure file sharing system, which will allow users to log in, store files, and share files with other users, while in the presence of attackers. 

Functionality:

InitUser: Given a new username and password, create a new user.

GetUser: Given a username and password, let the user log in if the password is correct.

User.StoreFile: For a logged-in user, given a filename and file contents, create a new file or overwrite an existing file.

User.LoadFile: For a logged-in user, given a filename, fetch the corresponding file contents.

User.AppendToFile: For a logged-in user, given a filename and additional file contents, append the additional file contents at the end of the existing file contents, while following some efficiency requirements.

User.CreateInvitation: For a logged-in user, given a filename and target user, generate an invitation UUID that the target user can use to gain access to the file.

User.AcceptInvitation: For a logged-in user, given an invitation UUID, obtain access to a file shared by a different user. Allow the recipient user to access the file using a (possibly different) filename of their own choosing.

User.RevokeAccess: For a logged-in user, given a filename and target user, revoke the target user’s access so that they are no longer able to access a shared file.




On top of all of this, there is a Datastore Adversary who can read and modify all name-value pairs, and add new name-value pairs, on Datastore where all information on files and logins are stored. They can modify Datastore at any time (but not in the middle of another function executing). The Datastore Adversary has a global view of Datastore; in other words, they can list out all name-value pairs that currently exist on Datastore. The Datastore Adversary can take snapshots of Datastore at any time. For example, they could write down all existing name-value pairs before a user calls StoreFile. Then, they could write down all existing name-value pairs after a user calls StoreFile and compare the difference to see which name-value pairs changed as a result of the function call. The Datastore Adversary can see when a user calls a function (e.g. if a user calls StoreFile, they know which user called it and when). The Datastore Adversary can view and record the content and metadata of all requests to the Datastore API. This means that they will know what the inputs and outputs to the functions are. The Datastore Adversary is not a user in the system, and will not collude with other users. However, the Datastore Adversary has a copy of your source code (Kerckhoff’s principle), and they could execute lines of your code on their own in order to modify Datastore in a way that mimics your code’s behavior.
