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
class Firewall(DynamicPolicy):
    def __init__(self):

        ### 1. DEFINE THE LPEC FUNCTION

        def lpec(f):
            # Packets with same source IP
            #  will have a same "state" (thus, same policy applied).
            return match(srcip=f['srcip'])
        ### 2. SET UP TRANSITION FUNCTIONS
        @transition
        def R0(self):
            # If True, return True. If False, return False.
            self.case(occured(self.event),self.event)
        @transition
        def R1(self):
            # If True, return True. If False, return False.
            self.case(occured(self.event),self.event)
        @transition
        def R2(self):
            # If True, return True. If False, return False.
            self.case(occured(self.event),self.event)
        @transition
        def R3(self):
            # If True, return True. If False, return False.
            self.case(occured(self.event),self.event)
        @transition
        def R4(self):
            # If True, return True. If False, return False.
            self.case(occured(self.event),self.event)
        @transition
        def R5(self):
            # If True, return True. If False, return False.
            self.case(occured(self.event),self.event)
        @transition
        def policy(self):
            self.case(is_True(V('R1')) | is_True(V('R3')),C(drop))
            self.default(C(identity))
        self.fsm_def = FSMDef(
                             R0=FSMVar(type=BoolType(),init=False,trans=R0),
                             R1=FSMVar(type=BoolType(),init=False,trans=R1),
                             R2=FSMVar(type=BoolType(),init=False,trans=R2),
                             R3=FSMVar(type=BoolType(),init=False,trans=R3),
                             R4=FSMVar(type=BoolType(),init=False,trans=R4),
                             R5=FSMVar(type=BoolType(),init=False,trans=R5),
                             policy=FSMVar(type=Type(policy,{drop,identity}),
                                           init=identity,
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
    pol = Firewall()
    # For NuSMV
    smv_str = fsm_def_to_smv_model(pol.fsm_def)
    mc = ModelChecker(smv_str,'Firewall')

    ## Add specs
    mc.add_spec("FAIRNESS\n  R0;")
    mc.add_spec("FAIRNESS\n  R1;")
    mc.add_spec("FAIRNESS\n  R2;")
    mc.add_spec("FAIRNESS\n  R3;")
    mc.add_spec("FAIRNESS\n  R4;")
    mc.add_spec("FAIRNESS\n  R5;")
    ### If infected event is true, next policy state is 'drop'
    mc.add_spec("SPEC AG (R1 | R3 -> AX policy=policy_1)")
    ### If infected event is false, next policy state is 'allow'
    mc.add_spec("SPEC AG (R0 | R2 | R4 | R5 -> AX policy=policy_2)")
    ### Policy state is 'allow' until infected is true.
    mc.add_spec("SPEC A [ policy=policy_2 U R1 | R3 ]")
    ### It is always possible to go back to 'allow'
    mc.add_spec("SPEC AG EF policy=policy_2")

    # Save NuSMV file
    mc.save_as_smv_file()

    # Verify
    mc.verify()

    # Ask deployment
    ask_deploy()

    # Return DynamicPolicy.
    # flood() will take for of forwarding for this simple example.
    return pol >> flood()
