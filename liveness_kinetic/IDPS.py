from pyretic.lib.corelib import *
from pyretic.lib.std import *

from pyretic.kinetic.fsm_policy import *
from pyretic.kinetic.drivers.json_event import JSONEvent
from pyretic.kinetic.smv.model_checker import *


#####################################################################################################
# * App launch
#   - pyretic.py pyretic.kinetic.apps.ids
#
# * Mininet Generation (in "~/pyretic/pyretic/kinetic" directory)
#   - sudo mn --controller=remote,ip=127.0.0.1 --mac --arp --switch ovsk --link=tc --topo=single,3
#
# * Start ping from h1 to h2
#   - mininet> h1 ping h2
#
# * Events to block traffic "h1 ping h2" (in "~/pyretic/pyretic/kinetic" directory)
#   - python json_sender.py -n infected -l True --flow="{srcip=10.0.0.1}" -a 127.0.0.1 -p 50001
#
# * Events to again allow traffic "h1 ping h2" (in "~/pyretic/pyretic/kinetic" directory)
#   - python json_sender.py -n infected -l False --flow="{srcip=10.0.0.1}" -a 127.0.0.1 -p 50001
#####################################################################################################

### Define a class for the application, subclassed from DynamicPolicy
class ids(DynamicPolicy):
    def __init__(self):
        
        ### 1. DEFINE THE LPEC FUNCTION
        
        def lpec(f):
            # Packets with same source IP
            #  will have a same "state" (thus, same policy applied).
            h1=f['srcip']
            h2=f['dstip']
            return ( match (srcip=h1 , dstip=h2 ) | match (srcip =h2 , dstip=h1 ) )
        
        
        ### 2. SET UP TRANSITION FUNCTIONS
        
        @transition
        def R0(self):
            self.case(occurred(self.event),self.event)
        def R1(self):
            if(h1==A and port = '2222'):
                self.case(is_true(V('!R1')),C(True))
            else:
                self.default(C(False))
        def R2(self):
            if(h1==A and h2==F):
                self.case(is_true(V('!R2')),C(True))
            else:
                self.default(C(False))
        def R3(self):
            if(h1==A and h2==D):
                self.case(is_true(V('!R3')),C(True))
            else:
                self.default(C(False))
        def R4(self):
            if(h1==A):
                self.case(is_true(V('!R4')),C(True))
            else:
                self.default(C(False))
        @transition
        def policy(self):
            # If "infected" is True, change policy to "drop"
            if('R4'):
                self.case(is_true(V('R4')),C(drop))
            elif('R3'):
                self.case(is_true(V('R3')),C(drop))
            self.default(C(fwd()))
            # Default policy is "indentity", which is "allow".
            self.default(C(identity))
        self.fsm_def =FSMDef(
                                     R0=FSMVar(type=BoolType(),inti=True,Trans=R0),
                                     R1=FSMVar(type=BoolType(),init=False,Trans=R1),
                                     R2=FSMVar(type=BoolType(),init=False,Trans=R2),
                                     R3=FSMVar(type=BoolType(),init=False,Trans=R3),
                                     R4=FSMVar(type=BoolType(),init=False,Trans=R4),
                                     policy=FSMVar(type=Type(policy,{drop,fwd()}),
                                                   init=fwd(),
                                                   trans=policy))
                                            ### 4. SET UP POLICY AND EVENT STREAMS
                                            
                                            ### This part pretty much remains same for any application
                                            fsm_pol = FSMPolicy(lpec,self.fsm_def)
                                            json_event = JSONEvent()
                                            json_event.register_callback(fsm_pol.event_handler)
                                            ### This part pretty much remains same for any application
                                            
                                            # Specify application class name here. (e.g., "ids")
        super(ids,self).__init__(fsm_pol)


def main():
    
    # DynamicPolicy that is going to be returned
    pol = ids()
    
    # For NuSMV
    smv_str = fsm_def_to_smv_model(pol.fsm_def)
    mc = ModelChecker(smv_str,'ids')
    
    ## Add specs
    mc.add_spec("FAIRNESS\n  infected;")
    
    ### If infected event is true, next policy state is 'drop'
    mc.add_spec("SPEC AG (infected -> AX policy=drop)")
    
    ### If infected event is false, next policy state is 'allow'
    mc.add_spec("SPEC AG (!infected -> AX policy=policy_1)")
    
    ### Policy state is 'allow' until infected is true.
    mc.add_spec("SPEC A [ policy=policy_1 U infected ]")
    
    ### It is always possible to go back to 'allow'
    mc.add_spec("SPEC AG EF policy=policy_1")
    
    # Save NuSMV file
    mc.save_as_smv_file()
    
    # Verify
    mc.verify()
    
    # Ask deployment
    ask_deploy()
    
    # Return DynamicPolicy.
    # flood() will take for of forwarding for this simple example.
    return pol >> flood()
