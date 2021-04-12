## file ##
# syn-worm-flows.py: - Tool to synthetically generate netflow data that would result from computer worms of 
#                       various types and with various behavioral parameters                                
#                                                                                                           
# details:  See https://www.nist.gov/programs-projects/trustworthy-intelligent-networks               
#                                                                                                           
# 2020/06/18 - Bardhan, Shuvo (IntlAssoc) <shuvo.bardhan@nist.gov>                            
#####    

""" 
This data/work was created by employees of the National Institute of Standards and Technology (NIST), 
an agency of the Federal Government. Pursuant to title 17 United States Code Section 105, works of NIST 
employees are not subject to copyright protection in the United States.  This data/work may be subject to 
foreign copyright.

The data/work is provided by NIST as a public service and is expressly provided “AS IS.” 
NIST MAKES NO WARRANTY OF ANY KIND, EXPRESS, IMPLIED OR STATUTORY, INCLUDING, WITHOUT LIMITATION, 
THE IMPLIED WARRANTY OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, NON-INFRINGEMENT AND DATA ACCURACY. 
NIST does not warrant or make any representations regarding the use of the data or the results thereof, 
including but not limited to the correctness, accuracy, reliability or usefulness of the data. 
NIST SHALL NOT BE LIABLE AND YOU HEREBY RELEASE NIST FROM LIABILITY FOR ANY INDIRECT, CONSEQUENTIAL, SPECIAL, 
OR INCIDENTAL DAMAGES (INCLUDING DAMAGES FOR LOSS OF BUSINESS PROFITS, BUSINESS INTERRUPTION, LOSS OF 
BUSINESS INFORMATION, AND THE LIKE), WHETHER ARISING IN TORT, CONTRACT, OR OTHERWISE, ARISING FROM OR 
RELATING TO THE DATA (OR THE USE OF OR INABILITY TO USE THIS DATA), EVEN IF NIST HAS BEEN ADVISED OF THE 
POSSIBILITY OF SUCH DAMAGES.

To the extent that NIST may hold copyright in countries other than the United States, you are hereby granted 
the non-exclusive irrevocable and unconditional right to print, publish, prepare derivative works and 
distribute the NIST data, in any medium, or authorize others to do so on your behalf, on a royalty-free 
basis throughout the world.

You may improve, modify, and create derivative works of the data or any portion of the data, and you may 
copy and distribute such modifications or works. Modified works should carry a notice stating that you changed 
the data and should note the date and nature of any such change. Please explicitly acknowledge the 
National Institute of Standards and Technology as the source of the data:  
Data citation recommendations are provided at https://www.nist.gov/open/license.

Permission to use this data is contingent upon your acceptance of the terms of this agreement and upon your 
providing appropriate acknowledgments of NIST’s creation of the data/work.

See: https://www.nist.gov/disclaimer

"""

"""

This code generates malicous traffic culminating from a propagating computer worm. 
Here we have modelled--(i) DDoS, (ii) Vertical Scan Attack, (iii) Horizontal Scan 
Attack, and (iv) FIN Scan Attack. The code takes the attack type along with the 
factors that affect computer worm propagation as input to create malcious traffic 
culminating from different variations of computer worms.

The factors and the attack type are hard coded in the main as--

Pop_Size = {1000000}     ## Population Size of the propagating computer worm
Scan_Rate = {10}         ## Scanning Rate of the propagating computer worm     
Susc_Prop = {0.75}       ## Susceptible Proportion of the propagating computer worm
Ninf= {1}                ## Number of initial infected hosts of the computer worm 
Code = {1,2,3,4}         ## Attack type 1--DDoS, 2--Horizontal Scan, 3--Vertical Scan and 4--Fin Scan

The user needs to modify these values to generate different variations of malicious traffic. 

Example 

    $ python Syn.py 

"""


####################################################   IMPORT   #######################################################
                                                    
import pprint 
import datetime 
import time 
import iptools 
import numpy as np 
import random 
import dateutil.parser as parser 
import sys 
import math 
import random 
import socket 
import struct 
from itertools import permutations 
import sys 
import os 
import os.path
    
#######################################################################################################################
    
####################################################   FILENAME   #####################################################
    
Time_filename = "Time.txt"                                                                          # Time # 
    
#######################################################################################################################
    
####################################################  VARIABLES  ######################################################
    
time_t    = []                                                              # List     : Time taken in each iteration # 
infection = []                                                              # List     : Infected Hosts               # 
i         = 0                                                               # Variable : Infected Number              # 
k         = 0                                                               # Variable : Inner Loop                   # 
j         = 0                                                               # Variable : Inner Loop                   # 
Lk2       = [ 'UAPRSF' , ' APRSF' , 'U PRSF' , 'UA RSF' , 'UAP SF' , 
'UAPR F' , 'UAPRS ' , '  PRSF' , 'U  RSF' , 'UA  SF' , 'UAP  F' , 'UAPR  ' , 
'   RSF' , 'U   SF' , 'UA   F' , 'UAP   ']                                                            # Unusual Flags #  
perms     = [ ''.join ( p ) for p in permutations ( random.choice ( Lk2 ) ) ]                         # Permutations  # 
    
#######################################################################################################################
    
####################################################  FUNCTIONS  ######################################################
    

    
### Function : Header ### 
def Header ( file_name , type ) : 
    
    """
    Function Header takes the filename and type (.csv or .txt) as input to create the header on these 
    files.
    
    Args : 
        file_name (str): filename for header to be placed
        type (str): .csv or .txt format
    """
    
    ### File Operation : Open ### 
    file = open ( file_name , 'w' )                                                                  # Malicious File #
    
    ## File Operation : Write ###
    if type == 1 : 
        file.write ( "#UNIX_SECS, DFLOWS, DPKTS, SRCADDR, DSTADDR, SRCPORT, DSTPORT, PROT, TCP_FLAGS")
    elif type == 2 :
        file.write ( "type|protocol|sIP|dIP|sPort|dPort|packets|bytes|sTime|duration|initialTCPflags|remainingTCPflags|" )
    file.write ( "\n" )
    
    ## File Operation : Close ### 
    file.close ()                                                                                    # Malicious File # 
    
    
### Function : DDOS ###     
def Malicious ( pop_size , scan_rate , susc_size , inf , code , count ) : 
    
    """
    Function Malicious takes population size, scanning rate, susceptible proportion, number of initial infected nodes, attack type, 
    and number of infections per iteration as input to generate netflows in .csv and .txt format. 
    
    Args : 
        pop_size (float)  : population size of scanning worm
        scan_rate (float) : scanning rate of computer worm
        susc_prop (float) : susceptible proportion of computer worm
        inf (float)       : number of initial infected hosts
        code (int)        : attack type
        count (int)       : time variable
        
    """
    
    ### Variable : Initialization ###
    time = int ( count ) * 5                                                          # Duration of Malicious Traffic #
    
    ### Filename ###
    if ( code == 1 ) :
        name = "DDoS"
    elif ( code == 2 ) :
        name = "Horiz"  
    elif ( code == 3 ) :
        name = "Vert" 
    elif ( code == 4 ) :
        name = "FIN"
    
    
    ### .txt ###    
    Malicious_filename = "[" + str ( int ( pop_size ) ) + "_" + str ( int ( scan_rate ) ) + "_" + str ( int ( susc_size ) ) + "_" + str ( int ( code ) ) + name + "_" + str ( time ) + "]" + ".txt"
    open ( Malicious_filename , 'w' ).close () 
    
    ### Header ###
    Header ( Malicious_filename , 2 )
    
    ### File Operation : Open ### 
    f0  = open ( Time_filename        , 'r' )                                                           # Time File      #  
    f1  = open ( Malicious_filename , 'a' )                                                             # Malicious File # 
    
    ### Variable : Initialization ### 
    port  = 0                                                                         # Port Counter                  # 
    ik_t  = 0                                                                         # Temp Variable (Unusual Flags) #
    st_t  = 0                                                                         # Temp Variable (Port Scan)     #
    n     = int ( code )                                                              # Code                          #
    
    ### IP Address Range ### 
    ip_internal  = iptools.IpRange ( '10.0.0.0' , '10.0.255.255' ).__iter__()         # Internal : IP Address Space # 
    ip_internal2 = iptools.IpRange ( '10.0.0.0' , '10.0.255.255' ).__iter__()         # Internal : IP Address Space # 
    
    
    ### Loop : For line in f0 ### 
    for line in f0 : 
    
        ### Data Extraction ### 
        ip , time , unix_t = line.split ( "," )                                                   # IP Address and Time # 
        time               = time.strip ()                                                        # Time Strip function #
        Unix_time          = unix_t.strip ()                                                      # Unix Strip Function #   
        #fmt               = '%Y-%m-%d %H:%M:%S.%f' 
        #time              = datetime.datetime.strptime ( time , fmt ) 
        
        ### Protocols ### 
        Src_ip          =  ip.strip ()                                                       # Source IP Address      #
        TCP_protocol    = '6'                                                                # TCP Protocol           #
        Dest_ip         = '10.0.100.1'                                                      # Destination IP Address #
        Packets         = int ( 1 )                                                          # Number of Packets      #
        Bytes           = random.randint ( 41 , 43 )                                         # Number of Bytes        #
        Dt              = time                                                               # Time in format         #
        Src_port        = random.randint ( 50000 , 65000 )                                   # Source Port            #
        Lk              = [8080,80]                                                          # List                   #
        Dest_port       = random.choice ( Lk )                                               # Destination Port       #
        Remaining_flags = '      '                                                           # Remaining Flags        #
        Duration        = random.randint ( 300 , 305 )                                       # Duration               #
        
        ### Random Number Generator ###
        r = random.randint ( 0 , 9 )                                                         # Random Integer         # 
        
        ### Conditional Statements : if ###
        if ( n == 1 ) :
               
            ### File Operation : Write ###
            #f1.write ( str ( Unix_time ) + "," + str ( Duration ) + "," + str ( Packets ) + "," + str ( Src_ip ) + "," + str ( Dest_ip ) + "," + str ( Src_port ) + "," + str ( Dest_port ) + "," + str ( TCP_protocol ) + "," + "    S " + "\n" )
            f1.write ( str ( "in" ) + str ( "|" ) + str ( TCP_protocol ) + str ( "|" ) + str ( Src_ip ) + str ( "|" ) + str ( Dest_ip ) + str ( "|" ) + str ( Src_port ) + str ( "|" ) + str ( Dest_port ) + str ( "|" ) + str ( Packets ) + str ( "|" ) + str ( Bytes ) + str ( "|" ) + str( Dt ) + str ( "|" ) + str ( "0.002" )+ str ( "|" ) + str ( "    S " ) + str ( "|" ) + str ( Remaining_flags ) + "\n" ) 
            if ( r==9 ) :
                #f1.write ( str ( Unix_time ) + "," +  str ( Duration ) + "," + str ( Packets ) + "," + str ( Dest_ip ) + "," + str ( Src_ip ) + "," + str ( Dest_port ) + "," + str ( Src_port ) + "," + str ( TCP_protocol ) + "," + " A  S " + "\n" )
                f1.write ( str ( "out" ) + str ( "|" ) + str ( TCP_protocol ) + str ( "|" ) + str ( Dest_ip ) + str ( "|" ) + str ( Src_ip ) + str ( "|" ) + str ( Dest_port ) + str ( "|" ) + str ( Src_port ) + str ( "|" ) + str ( Packets ) + str ( "|" ) + str ( Bytes ) + str ( "|" ) + str( Dt ) + str ( "|" ) + str ( "0.002" )+ str ( "|" ) + str ( " A  S " ) + str ( "|" ) + str ( Remaining_flags ) + "\n" ) 
            
        
        elif ( n == 2 ) : 
            if ( port < 65536 ) :
                
                ### Variable : Initialization ###
                Dest_ip   = '10.0.100.9'                                       # Destination IP Address # 
                Dest_port = port                                               # Port Number            # 
            
                ### File Operation : Write ### 
                f1.write ( str ( "in" ) + str ( "|" ) + str ( TCP_protocol ) + str ( "|" ) + str ( Src_ip ) + str ( "|" ) + str ( Dest_ip ) + str ( "|" ) + str ( Src_port ) + str ( "|" ) + str ( Dest_port ) + str ( "|" ) + str ( Packets ) + str ( "|" ) + str ( Bytes ) + str ( "|" ) + str( Dt ) + str ( "|" ) + str ( "0.002" )+ str ( "|" ) + str ( '    S ' ) + str ( Remaining_flags ) + str ( "|" ) + "\n" )
                if ( r == 9 ) : 
                    f1.write ( str ( "out" ) + str ( "|" ) + str ( TCP_protocol ) + str ( "|" ) + str ( Dest_ip ) + str ( "|" ) + str ( Src_ip ) + str ( "|" ) + str ( Dest_port ) + str ( "|" ) + str ( Src_port ) + str ( "|" ) + str ( Packets ) + str ( "|" ) + str ( Bytes ) + str ( "|" ) + str( Dt ) + str ( "|" ) + str ( "0.002" )+ str ( "|" ) + str ( ' A    ' ) + str ( Remaining_flags ) + str ( "|" ) + "\n" )
                    f1.write ( str ( "in"  ) + str ( "|" ) + str ( TCP_protocol ) + str ( "|" ) + str ( Src_ip ) + str ( "|" ) + str ( Dest_ip ) + str ( "|" ) + str ( Src_port ) + str ( "|" ) + str ( Dest_port ) + str ( "|" ) + str ( Packets ) + str ( "|" ) + str ( Bytes ) + str ( "|" ) + str( Dt ) + str ( "|" ) + str ( "0.002" )+ str ( "|" ) + str ( '   R  ' ) + str ( Remaining_flags ) + str ( "|" ) + "\n" )
            
                ### Increment : port ###
                port += 1                                                                               # Port Number #
                
                
        ### Try Statement ###
        elif ( n == 3 ) : 
            try :
               
                ### If Statement ### 
                if ( next ( ip_internal ).strip() != '10.0.255.255' ) : 
                    
                    ### Variables ### 
                    Dest_ip_1 = next ( ip_internal ) 
                                       
                    ### File Operation : Write ###
                    f1.write ( str ( "in" ) + str ( "|" ) + str( TCP_protocol ) + str ( "|" ) + str ( Src_ip ) + str ( "|" ) + str ( Dest_ip_1 ) + str ( "|" ) + str ( Src_port ) + str ( "|" ) + str ( Dest_port ) + str ( "|" ) + str ( Packets ) + str ( "|" ) + str ( Bytes ) + str ( "|" ) + str( Dt ) + str ( "|" ) + str ( "0.002" )+ str ( "|" ) + str ( '    S ' ) + str ( "|" ) + "\n" )  
                    if ( r == 9 ) : 
                        f1.write ( str ( "out" ) + str ( "|" ) + str ( TCP_protocol ) + str ( "|" ) + str ( Dest_ip_1 ) + str ( "|" ) + str ( Src_ip ) + str ( "|" ) + str ( Dest_port ) + str ( "|" ) + str ( Src_port ) + str ( "|" ) + str ( Packets ) + str ( "|" ) + str ( Bytes ) + str ( "|" ) + str( Dt ) + str ( "|" ) + str ( "0.002" ) + str ( "|" ) + str ( ' A    ' ) + str ( "|" ) + "\n" ) 
                        f1.write ( str ( "in"  ) + str ( "|" ) + str ( TCP_protocol ) + str ( "|" ) + str ( Src_ip ) + str ( "|" ) + str ( Dest_ip_1 ) + str ( "|" ) + str ( Src_port ) + str ( "|" ) + str ( Dest_port ) + str ( "|" ) + str ( Packets ) + str ( "|" ) + str ( Bytes ) + str ( "|" ) + str( Dt ) + str ( "|" ) + str ( "0.002" ) + str ( "|" ) + str ( '   R  ' ) + str ( "|" ) + "\n" ) 
                
            ### Exception Handling ###
            except StopIteration :
                st_t += 1                                      # Increment : Temp Variable (Horiz. Scan) #
                
                
        elif ( n == 4 ) : 
            try :
            
                ### If Statement ### 
                if ( next ( ip_internal2 ).strip() != '10.0.255.255' ) : 
                    
                    ### Variable : Update ### 
                    Dest_ip_2 = next ( ip_internal2 )                           # Destination IP Address #
                                       
                    ### File Operation : Write ###
                    f1.write ( str ( "in" ) + str ( "|" ) + str( TCP_protocol ) + str ( "|" ) + str ( Src_ip ) + str ( "|" ) + str ( Dest_ip_2 ) + str ( "|" ) + str ( Src_port ) + str ( "|" ) + str ( Dest_port ) + str ( "|" ) + str ( Packets ) + str ( "|" ) + str ( Bytes ) + str ( "|" ) + str( Dt ) + str ( "|" ) + str ( "0.002" ) + str ( "|" ) + str ( '     F' ) + str ( "|" ) + "\n" ) 
                    if ( r!=9 ) : 
                        f1.write ( str ( "out" ) + str ( "|" ) + str ( TCP_protocol ) + str ( "|" ) + str ( Dest_ip_2 ) + str ( "|" ) + str ( Src_ip ) + str ( "|" ) + str ( Dest_port ) + str ( "|" ) + str ( Src_port ) + str ( "|" ) + str ( Packets ) + str ( "|" ) + str ( Bytes ) + str ( "|" ) + str( Dt ) + str ( "|" ) + str ( "0.002" )+ str ( "|" ) + str ( '   R  ' ) + str ( "|" ) + "\n" ) 
            
            ### Exception Handling ###
            except StopIteration :
                st_t += 1                                           # Increment Temp Variable (FIN Scan) #
                
                
        elif ( n == 5 ) : 
            if ( ik_t<1000 ) : 
            
                ### Variable : Initialization ###
                flag = random.choice ( perms )                                    # Flag (Unusual Flags) #
                
                ### File Operation : Write ###
                f1.write ( str ( "in" ) + str ( "|" ) + str ( TCP_protocol ) + str ( "|" ) + str ( Src_ip ) + str ( "|" ) + str ( Dest_ip_2 ) + str ( "|" ) + str ( Src_port ) + str ( "|" ) + str ( Dest_port ) + str ( "|" ) + str ( Packets ) + str ( "|" ) + str ( Bytes ) + str ( "|" ) + str( Dt ) + str ( "|" ) + str ( "0.002" )+ str ( "|" ) + str ( flag ) + "\n" )
                
                ### Increment : ik_t ###
                ik_t += 1                                                    # Increment Temp Variable (Unusual Flag) #
    
                ### Display ###
                print (Malicious_filename_1)
                print (Malicious_filename_2)
                
### Function : Curve ###
def Curve ( pop_size , scan_rate , susc_size , inf ) : 
    
    """ 
    Function Curve generates the list of infected IP addresses per iteration of the scanning computer worm and stores it in Time.txt.
    
    Args : 
        pop_size (float) : population size of scanning worm
        scan_rate (float) : scanning rate of scanning worm
        susc_size (float) : susceptible size of scanning worm
        inf (int) : number of initial infected hosts
    
    """
    
    ## Initialization ## 
    L     = []                                                                                      # List    : L     # 
    Inf   = []                                                                                      # List    : Inf   # 
    count = 0                                                                                       # Integer : count # 
    
    ## Loop : While inf is less than susc_size ### 
    while ( inf < susc_size ) : 
        
        ## Data Generation : Newly Infected Hosts ## 
        new = ( susc_size - inf ) * ( 1.0 - math.pow ( (  1.0 - ( 1.0 / ( pop_size ) ) )  , ( scan_rate * inf ) ) ) 
        new = round ( new , 0 ) 
        
        ## Update ##
        L   = L + [ new ] 
        inf += new 
        Inf = Inf + [ inf ] 
        
        ## Increment : count ##
        count += 1 
        
    ## Return ## 
    return ( Inf , L , count ) 
    
    
### Function : Main ###
def Generator ( pop_size , scan_rate , susc_size , inf , code ) : 
    
    """
    Function Generator genereates the malicious datasets by initially calling function Curve and then function Malicious.
    
    Args : 
        pop_size (float) : Population Size of Scanning Worm 
        scan_rate (float) : Scanning Rate of Computer Worm 
        susc_size (float) : Susceptible Size o Computer Worm 
        inf (int) : Number of initial infected hosts
        code (int) : Attack Type 
    
    """
    
    ### Input ### 
    pop_size  = float ( pop_size  )                                                # Population Size                  #
    scan_rate = float ( scan_rate )                                                # Scanning Rate                    #
    susc_size = float ( susc_size )                                                # Susceptible Size                 #
    inf       = float ( inf       )                                                # Number of Initial Infected nodes #
    code      = int   ( code      )                                                # Code                             #
    
    ### Data Generation ### 
    inf , res , count = Curve ( pop_size , scan_rate , susc_size , inf )           # Curve                    # 
    r                 = iptools.IpRange ( '10.0/16' )                             # IP Space : Address Space # 
    
    ### Data Generation : Random Infected IP Address (Outside NIST) ### 
    z = [] 
    i = 0 
    
    ### Loop : While i is less than susc_size ###
    while ( i < susc_size ) : 
    
        ### Random IP Address Generation ###
        p = socket.inet_ntoa ( struct.pack ( '>I' , random.randint ( 1 , 0xffffffff ) ) )         # Random IP Address #
        p = p.strip () 
        
        ### Insert into List ### 
        if ( p not in r ) : 
            z.append ( p ) 
            
            ### Increment : i ### 
            i += 1 
    
    ### Loop : While i is less than count ### 
    i=0 
    while ( i < count ) : 
    
        ### Global Variable ### 
        global time_t 
        
        ### Conversion to Microseconds ### 
        temp   = 300000000 / res [i] 
        time_t = time_t + [ temp ] 
        
        ### Increment : i ### 
        i += 1 
    
    ### Variable : Initialization ### 
    b_time   = datetime.datetime.now ()                                                                     # Time # 
    unixtime = time.mktime ( b_time.timetuple () )                                                       # unixtime #
       
    ### File Operations : Open ### 
    open ( Time_filename , 'w' ).close () 
    f = open ( Time_filename , 'a' ) 
    
    ### Loop : While i is less than count ### 
    i = 0 
    k = 0 
    while ( i < count ) : 
        
        ### Loop : While j is less than res[i] ###
        j = 0 
        while ( j < res[i] ) : 
        
            ### Data : Format ### 
            Dt  = b_time.strftime ( '%Y/%m/%dT%H:%M:%S' ) 
            
            ### File Operation : Write # 
            f.write ( str ( z[k] ) + "," + str ( Dt ) + "," + str ( unixtime ) ) 
            f.write ( "\n" ) 
            
            ### Update : time ### 
            b_time   = b_time + datetime.timedelta ( microseconds = time_t[i] ) 
            b_time   = b_time.strftime ( "%Y-%m-%d %H:%M:%S.%f" )
            b_time   = datetime.datetime.strptime ( b_time , "%Y-%m-%d %H:%M:%S.%f" )
            unixtime = time.mktime ( b_time.timetuple () )
        
            ### Increment : k & j ### 
            k += 1 
            j += 1 
        
        ### Increment : i ### 
        i += 1 
    
    print ( "Done!!" )
    ### Malicious Traffic ### 
    Malicious ( pop_size , scan_rate , susc_size , inf , code , count ) 
    

def main () : 
    
    """
    
    main consists of a nested for loop which takes the factors that affect worm propagation and the attack type as input to 
    generate malicious traffic culminating from different variations of computer worms.
    
    """
    
    ### Begin Time ###
    begin_time_main = datetime.datetime.now ()                                                           # Begin Time #
    
    ### Lists ###
    code      = [1,2,3,4]                                             # Code Number                      # 
    Pop_Size  = [64000,128000]                                        # Population Size                  # 
    Scan_Rate = [10,50]                                               # Scanning Rate                    # 
    Susc_Prop = [0.25,0.75]                                           # Susceptible Proportion           # 
    Ninf      = [1]                                                   # Number of Initial Infected Nodes # 
    
    
    ### Variable : Initialization ###
    n = len (Pop_Size) * len (Scan_Rate) * len (Susc_Prop) * len (Ninf) * len (code) 
    
    ### Nested For Loop to generate malicious traffic ###
    for c in code :
        for p in Pop_Size : 
            for sr in Scan_Rate : 
                for sp in Susc_Prop : 
                    for i in Ninf : 
                        s_p = int ( sp * p ) 
                        Generator ( p , sr , s_p , i , c ) 
    
    ### End Time ###
    end_time_main = datetime.datetime.now ()                                                               # End Time # 
    
    ### Display ### 
    print ( "Experiment Ends" ) 
    print ( "Number of runs (n) :: " + str ( n ) ) 
    print ( "\nTime to generate Malicious Traffic ( in minutes ) :: " + str ( ( end_time_main - begin_time_main ).total_seconds() / 60 ) ) 
    
#######################################################################################################################
    
### Main ###
if __name__ == "__main__": 
    main() 
    






