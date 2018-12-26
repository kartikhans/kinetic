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
class monitor(DynamicPolicy):
    def __init__(self):
        v1=2
        v2=7
        m=10
        rates=range(m)

    ### 1. DEFINE THE LPEC FUNCTION
        def lpec(f):
            return match(srcip=f['srcip'])

    ### 2. SET UP TRANSITION FUNCTIONS
        @transition
        def counter(self):
            for i in range(m):
                self.case(V('counter')==C(i),C(i+1))
            self.default(C(0))
        @transition
        def policy(self):
        # If "infected" is True, change policy to "drop"
            self.case((V('counter')>=v2),C(drop))
        # Default policy is "indentity", which is "allow".
            self.default(C(identity))
    ### 3. SET UP THE FSM DESCRIPTION

        self.fsm_def =FSMDef(
                         counter=FSMVar(type=Type(int,set(rates)),init=0,trans=counter),
                         policy=FSMVar(type=Type(Policy,{drop,identity}),
                                       init=identity,
                                       trans=policy))
        ### 4. SET UP POLICY AND EVENT STREAMS
        fsm_pol = FSMPolicy(lpec,self.fsm_def)
        json_event = JSONEvent()
        json_event.register_callback(fsm_pol.event_handler)
        super(monitor,self).__init__(fsm_pol)
def main():

    # DynamicPolicy that is going to be returned
    pol = monitor()

    # For NuSMV
    smv_str = fsm_def_to_smv_model(pol.fsm_def)
    mc = ModelChecker(smv_str, 'monitor')

    ## Add specs
    ### If infected event is true, next policy state is 'drop'
    mc.add_spec("SPEC AG ((counter>=v2) -> AX policy=drop)")
    ### If infected event is false, next policy state is 'allow'
    mc.add_spec("SPEC AG ((counter>=0) & (counter<v2) -> AX policy=policy_2)")

    ### Policy state is 'allow' until infected is true.
    mc.add_spec("SPEC A [ policy=policy_1 U (counter>=v2 and counter<m) ]")
    mc.add_spec("SPEC AG (EF policy=policy_1)")
    mc.add_spec("SPEC policy=policy_1 -> EX policy=policy_1")
    mc.add_spec("SPEC AG (policy=policy_1 -> EF policy=policy_2)")

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
