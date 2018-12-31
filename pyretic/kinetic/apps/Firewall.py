
from pyretic.lib.corelib import *
from pyretic.lib.std import *

from pyretic.kinetic.fsm_policy import *
from pyretic.kinetic.drivers.json_event import JSONEvent
from pyretic.kinetic.smv.model_checker import *
from pyretic.kinetic.util.rewriting import *
from pyretic.kinetic.apps.mac_learner import *

#####################################################################################################
# * App launch
#   - pyretic.py pyretic.kinetic.apps.gardenwall
#
# * Mininet Generation (in "~/pyretic/pyretic/kinetic" directory)
#   - sudo mn --controller=remote,ip=127.0.0.1 --mac --arp --switch ovsk --link=tc --topo=single,3
#
# * Start ping from h1 to h2
#   - mininet> h1 ping h2
#
# * Send Event to block traffic "h1 ping h2" (in "~/pyretic/pyretic/kinetic" directory)
#   - python json_sender.py -n infected -l True --flow="{srcip=10.0.0.1}" -a 127.0.0.1 -p 50001
#
# * Now, make h1's flow not be affected by IDS infection event(in "~/pyretic/pyretic/kinetic" directory)
#   h1's traffic will be forwarded to 10.0.0.3.
#   - python json_sender.py -n exempt -l True --flow="{srcip=10.0.0.1}" -a 127.0.0.1 -p 50001
#
# * Events to now allfow traffic again (in "~/pyretic/pyretic/kinetic" directory)
#   - python json_sender.py -n infected -l False --flow="{srcip=10.0.0.1}" -a 127.0.0.1 -p 50001
#####################################################################################################

class Firewall(DynamicPolicy):
    def __init__(self):

        ### DEFINE THE LPEC FUNCTION

        def lpec(f):
            return match(srcip=f['srcip'])

        ## SET UP TRANSITION FUNCTIONS
        @transition
        def R1(self):
            self.case(occurred(self.event),self.event)

        @transition
        def R3(self):
            self.case(occurred(self.event),self.event)

        @transition
        def policy(self):
            # If exempt, redirect to gardenwall.
            #  - rewrite dstip to 10.0.0.3
            # If infected, drop
            self.case(is_true(V('R1')) or is_true(V('R3')) ,C(drop))

            # Else, identity
            self.default(C(identity))


        ### SET UP THE FSM DESCRIPTION

        self.fsm_def = FSMDef(
            R1=FSMVar(type=BoolType(),
                            init=False,
                            trans=R1),
            R3=FSMVar(type=BoolType(),
                            init=False,
                            trans=R3),
            policy=FSMVar(type=Type(Policy,{drop,identity}),
                          init=identity,
                          trans=policy))

        ### SET UP POLICY AND EVENT STREAMS

        fsm_pol = FSMPolicy(lpec,self.fsm_def)
        json_event = JSONEvent()
        json_event.register_callback(fsm_pol.event_handler)

        super(Firewall,self).__init__(fsm_pol)


def main():
    pol = Firewall()

    # For NuSMV
    smv_str = fsm_def_to_smv_model(pol.fsm_def)
    mc = ModelChecker(smv_str,'Firewall')

    ## Add specs
    mc.add_spec("FAIRNESS\n  R1;")
    mc.add_spec("FAIRNESS\n  R3;")

    # Now, traffic is dropped only when exempt is false and infected is true
    mc.add_spec("SPEC AG (R1 -> AX policy=drop)")
    mc.add_spec("SPEC AG (R3 -> AX policy=drop)")
    # If infected is false, next policy state is always 'allow'
    mc.add_spec("SPEC AG (!R1 -> AX policy=identity)")
    mc.add_spec("SPEC AG (!R3 -> AX policy=identity)")

    ### Policy state is 'allow' until infected is true.
    mc.add_spec("SPEC A [ policy=policy_2 U (R1 or R3) ]")

    # Save NuSMV file
    mc.save_as_smv_file()

    # Verify
    mc.verify()

    # Ask deployment
    ask_deploy()

    return pol >> flood()
