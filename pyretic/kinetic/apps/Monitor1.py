from pyretic.lib.corelib import *
from pyretic.lib.std import *

from pyretic.kinetic.fsm_policy import *
from pyretic.kinetic.drivers.json_event import JSONEvent
from pyretic.kinetic.smv.model_checker import *
from pyretic.kinetic.util.rewriting import *
from pyretic.kinetic.apps.mac_learner import *
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
class Monitor1(DynamicPolicy):
    count=0
    def __init__(self):
        v1=2
        v2=7
        m=10
        rates=[0,v1,v2,m]
        Monitor1.count+=1
    ### 1. DEFINE THE LPEC FUNCTION
        def lpec(f):
            return match(srcip=f['srcip'])

    ### 2. SET UP TRANSITION FUNCTIONS
        @transition
        def counter(self):
            pol_change=False
            if(Monitor1.count>=rates[2] and Monitor1.count<rates[3]):
                pol_change=True
            self.case(is_true(V('pol_change')),C(True))
        @transition
        def policy(self):
        # If "infected" is True, change policy to "drop"
            self.case(is_true(V('counter')),C(drop))
        # Default policy is "indentity", which is "allow".
            self.default(C(identity))
    ### 3. SET UP THE FSM DESCRIPTION

        self.fsm_def =FSMDef(
                         counter=FSMVar(type=BoolType(),init=False,trans=counter),
                         policy=FSMVar(type=Type(Policy,{drop,identity}),
                                       init=identity,
                                       trans=policy))
        ### 4. SET UP POLICY AND EVENT STREAMS
        fsm_pol = FSMPolicy(lpec,self.fsm_def)
        json_event = JSONEvent()
        json_event.register_callback(fsm_pol.event_handler)
        super(Monitor1,self).__init__(fsm_pol)
def main():

    # DynamicPolicy that is going to be returned
    pol = Monitor1()

    # For NuSMV
    smv_str = fsm_def_to_smv_model(pol.fsm_def)
    mc = ModelChecker(smv_str, 'Monitor1')

    ## Add specs
    mc.add_spec("FAIRNESS\n  counter;")
    ### If infected event is true, next policy state is 'drop'
    mc.add_spec("SPEC AG (counter -> AX policy=drop)")
    ### If infected event is false, next policy state is 'allow'
    mc.add_spec("SPEC AG (!counter -> AX policy=policy_1)")

    ### Policy state is 'allow' until infected is true.
    mc.add_spec("SPEC A [ policy=policy_1 U counter ]")

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
