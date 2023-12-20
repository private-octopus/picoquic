#If you use threads, add -pthread here.
COMPILERFLAGS = -g -Wall -Wextra -Wno-sign-compare

#Any libraries you might need linked in.
#LINKLIBS = -lm

#The components of each program. When you create a src/foo.c source file, add obj/foo.o here, separated
#by a space (e.g. SOMEOBJECTS = obj/foo.o obj/bar.o obj/baz.o).
SERVEROBJECTS = obj/http_server.o
CLIENTOBJECTS = obj/http_client.o


#Every rule listed here as .PHONY is "phony": when you say you want that rule satisfied,
#Make knows not to bother checking whether the file exists, it just runs the recipes regardless.
#(Usually used for rules whose targets are conceptual, rather than real files, such as 'clean'.
#If you DIDNT mark clean phony, then if there is a file named 'clean' in your directory, running
#`make clean` would do nothing!!!)
.PHONY: all clean

#The first rule in the Makefile is the default (the one chosen by plain `make`).
#Since 'all' is first in this file, both `make all` and `make` do the same thing.
#(`make obj server client talker listener` would also have the same effect).
all : obj http_server http_client

#$@: name of rule's target: server, client, talker, or listener, for the respective rules.
#$^: the entire dependency string (after expansions); here, $(SERVEROBJECTS)
#CC is a built in variable for the default C compiler; it usually defaults to "gcc". (CXX is g++).
http_server: $(SERVEROBJECTS)
	$(CXX) $(COMPILERFLAGS) $^ -o $@ $(LINKLIBS)



#So, how does all of this work? This rule is saying 
#
#"I am how you make the thing called client. If the thing called client is required, but doesn't 
#exist / is out of date, then the way to make it is to run 
#`$(CC) $(COMPILERFLAGS) $^ -o $@ $(LINKLIBS)`. 
#But, you can't start doing that until you are sure all of my dependencies ($(CLIENTOBJECTS)) are up to date."
#
#In this case, CLIENTOBJECTS is just obj/client.o. So, if obj/client.o doesn't exist or is out of date, 
#make will first look for a rule to build it. That rule is the 'obj/%.o' one, below; the % is a wildcard.
http_client: $(CLIENTOBJECTS)
	$(CXX) $(COMPILERFLAGS) $^ -o $@ $(LINKLIBS)




#RM is a built-in variable that defaults to "rm -f".
clean :
	$(RM) obj/*.o http_server http_client

#$<: the first dependency in the list; here, src/%.c. (Of course, we could also have used $^).
#The % sign means "match one or more characters". You specify it in the target, and when a file
#dependency is checked, if its name matches this pattern, this rule is used. You can also use the % 
#in your list of dependencies, and it will insert whatever characters were matched for the target name.
obj/%.o: src/%.cpp
	$(CXX) $(COMPILERFLAGS) -c -o $@ $<
obj:
	mkdir -p obj

