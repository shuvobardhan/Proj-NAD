# syn-worm-flow.py

## Introduction :
 
This tool has been created to generate malicious traffic culminating from a random scanning computer 
worm. The malcious traffic created is in netflow format (.txt). The malcious traffic that we 
have modelled here are--

1. DDoS attack.
2. Vertical Scan attack
3. Random Scan attack.
4. Horizontal Scan attack.

---
## Installation Requirements :

1. Python 3.7.3 or above
2. Iptools 0.7.0
3. pprint 0.1
4. DateTime 4.3
5. numpy 1.18.5
6. python-dateutil 2.8.1

---

## Pseudo Code : 

In main, a nested for loop creates different variations of malicious traffic based culminating from a 
propagating computert worm. It does so by calling function Generator, which takes 5 inputs--

1. Population Size (Pop_Size)--population size of the scanning worm ;
2. Suscpetible Proportion (Susc_Prop)--size of the susceptible set of computers within the population size ; 
3. Scanning Rate (Scan_Rate)--scanning rate of computer worm ;
4. Number of Initial Infected Hosts (Ninf)--number of the initial set of infected hosts. ; and
5. Type of Attack (Code)--attack type from the attacks that we have modelled.

The output of the function Generator is a set of malicious traffic culminating from the different variations of 
computer worms by taking these values.  

---

## Example :
	
In the example folder, we have created a sample set of malicious traffic for the attacks that we have 
modelled--(i) DDoS (1) ; (ii) Horizontal Scan (2) ; (iii) Vertical Scan (3) ; and (iv) Fin Scan (4) using 
these values--

1. Pop_Size    = {1000000}
2. Susc_Prop   = {0.75}
3. Scan_Rate   = {50}
4. Ninf        = {1}
5. Code        = {1, 2, 3, 4}

To run the code--

	$ python Syn_worms_flow.py

The malicious datasets will be created in the current directory.