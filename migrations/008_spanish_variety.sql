-- ============================================================
-- Cluff Learning Systems — Spanish Coach topic variety
-- Migration 008
--
-- Gives Spanish Coach a bank of 100 simple everyday conversation
-- scenarios and chooses the least-recently-used one for each learner.
-- This keeps the curriculum/review targets intact while changing the
-- conversational angle from session to session.
--
-- Idempotent and safe to re-run.
-- ============================================================

INSERT INTO spanish_scenarios
  (key, title, description, opening_instruction, target_domains, min_level, enabled, sort_order)
VALUES
('everyday_001','Breakfast','Talk about breakfast foods and what the learner likes to eat.','Start directly with one very easy question about breakfast. Use today''s curriculum words and review targets naturally inside the breakfast conversation.','["food","preferences"]'::jsonb,'novice_low',true,201),
('everyday_002','Favorite snack','Talk about a favorite snack and simple choices.','Ask a tiny either-or question about snacks. Let the learner choose, then follow their answer instead of running a script.','["food","preferences"]'::jsonb,'novice_low',true,202),
('everyday_003','What is in the fridge?','Imagine opening the refrigerator and noticing what is inside.','Ask what one thing might be in the refrigerator. Keep it concrete and playful.','["food","objects"]'::jsonb,'novice_low',true,203),
('everyday_004','Making a sandwich','Pretend to make a simple sandwich together.','Ask what should go on a sandwich first. Build the pretend sandwich one choice at a time.','["food","sequence"]'::jsonb,'novice_low',true,204),
('everyday_005','Ice cream shop','Choose an ice cream flavor and size.','Pretend you are at an ice cream counter. Ask one simple choice question and react naturally to the answer.','["food","choices"]'::jsonb,'novice_low',true,205),
('everyday_006','Pizza toppings','Choose toppings for a pretend pizza.','Ask what should go on a pizza. Accept silly but age-appropriate answers and keep the exchange conversational.','["food","choices"]'::jsonb,'novice_low',true,206),
('everyday_007','Fruit basket','Talk about fruits, colors, and favorites.','Ask the learner to pick one fruit from a pretend basket, then ask one natural follow-up.','["food","colors"]'::jsonb,'novice_low',true,207),
('everyday_008','Packing lunch','Decide what to put in a lunch bag.','Ask what one item belongs in the lunch bag. Keep adding or comparing items naturally.','["food","school"]'::jsonb,'novice_low',true,208),
('everyday_009','Cooking dinner','Talk about making a simple dinner.','Ask what the learner would like for dinner or what should be cooked first.','["food","family"]'::jsonb,'novice_low',true,209),
('everyday_010','A strange new food','Imagine trying an unfamiliar but ordinary food.','Ask whether the learner would try a harmless unusual food and why only if their level supports why questions.','["food","opinions"]'::jsonb,'novice_low',true,210),
('everyday_011','Morning routine','Talk about getting ready in the morning.','Ask what the learner does first after waking up. Adapt the question to their Spanish age.','["routine","time"]'::jsonb,'novice_low',true,211),
('everyday_012','Bedtime routine','Talk about getting ready for bed.','Ask one easy question about bedtime, pajamas, brushing teeth, or a bedtime story.','["routine","home"]'::jsonb,'novice_low',true,212),
('everyday_013','Getting dressed','Choose clothes for today.','Ask what the learner is wearing or what they would choose to wear today.','["clothing","colors"]'::jsonb,'novice_low',true,213),
('everyday_014','Lost shoe','Pretend one shoe is missing and figure out where it could be.','Open with a playful question about where the missing shoe might be. Use location words naturally.','["clothing","location"]'::jsonb,'novice_low',true,214),
('everyday_015','Cleaning a room','Talk about putting a few things away.','Ask where one familiar object should go in a room.','["home","location"]'::jsonb,'novice_low',true,215),
('everyday_016','Laundry day','Sort simple clothes by type or color.','Ask which item goes in the laundry or which color pile it belongs in.','["clothing","colors"]'::jsonb,'novice_low',true,216),
('everyday_017','Chores','Talk about one small household chore.','Ask which simple chore the learner does or would rather do. Keep it light.','["home","actions"]'::jsonb,'novice_low',true,217),
('everyday_018','A messy table','Decide what belongs on a table and what does not.','Name or ask about one object on a pretend messy table and let the learner help sort it.','["home","objects"]'::jsonb,'novice_low',true,218),
('everyday_019','Opening the curtains','Talk about what the weather looks like outside.','Pretend to open the curtains and ask what the learner thinks the weather is like.','["weather","home"]'::jsonb,'novice_low',true,219),
('everyday_020','Power went out','Imagine the lights went out for a moment.','Ask what the learner would do if the lights went out. Keep it calm, ordinary, and non-scary.','["home","actions"]'::jsonb,'novice_low',true,220),
('everyday_021','Sunny day','Talk about what to do on a sunny day.','Ask what the learner likes to do when it is sunny.','["weather","activities"]'::jsonb,'novice_low',true,221),
('everyday_022','Rainy day','Talk about rain, umbrellas, and indoor activities.','Ask whether it is fun to play in rain or what the learner does when it rains.','["weather","activities"]'::jsonb,'novice_low',true,222),
('everyday_023','Cold day','Choose clothes and activities for cold weather.','Ask what someone needs to wear when it is cold.','["weather","clothing"]'::jsonb,'novice_low',true,223),
('everyday_024','Hot day','Talk about staying cool on a hot day.','Ask what the learner likes to drink or do when it is hot.','["weather","activities"]'::jsonb,'novice_low',true,224),
('everyday_025','Windy day','Imagine a very windy afternoon.','Ask what might blow around in the wind or what is fun to do on a windy day.','["weather","objects"]'::jsonb,'novice_low',true,225),
('everyday_026','Cloud shapes','Look at pretend clouds and imagine shapes.','Ask what one cloud looks like. At very low levels, offer two simple choices.','["weather","imagination"]'::jsonb,'novice_low',true,226),
('everyday_027','Best season','Talk about favorite seasons and simple reasons.','Ask which season the learner likes best. Ask for a reason only if their Spanish age supports it.','["weather","preferences"]'::jsonb,'novice_low',true,227),
('everyday_028','After a storm','Talk about puddles, wet grass, and what changed outside.','Ask what the learner might see outside after rain.','["weather","nature"]'::jsonb,'novice_low',true,228),
('everyday_029','Snow day imagination','Imagine a snow day even if snow is unusual where they live.','Ask what the learner would build or do in snow. Keep it playful and simple.','["weather","imagination"]'::jsonb,'novice_low',true,229),
('everyday_030','Weather tomorrow','Make a simple guess about tomorrow''s weather.','Ask what weather the learner hopes for tomorrow.','["weather","future"]'::jsonb,'novice_low',true,230),
('everyday_031','Dog at the park','Talk about seeing a friendly dog at a park.','Ask what the dog looks like or what it is doing.','["animals","park"]'::jsonb,'novice_low',true,231),
('everyday_032','Cat on a chair','Talk about a cat and where it is sitting.','Ask where the cat is or what it might do next.','["animals","location"]'::jsonb,'novice_low',true,232),
('everyday_033','Bird at the window','Talk about a bird outside the window.','Ask what color the bird is or what it is doing.','["animals","colors"]'::jsonb,'novice_low',true,233),
('everyday_034','Farm animals','Choose a favorite farm animal.','Ask the learner to pick between two farm animals, then follow their choice.','["animals","preferences"]'::jsonb,'novice_low',true,234),
('everyday_035','Zoo visit','Imagine seeing one or two zoo animals.','Ask which animal the learner wants to see first. Do not turn it into a long list quiz.','["animals","choices"]'::jsonb,'novice_low',true,235),
('everyday_036','Tiny bug','Notice a harmless tiny bug outside.','Ask what color or size the bug is, or where it is going.','["animals","nature"]'::jsonb,'novice_low',true,236),
('everyday_037','Animal sounds','Guess an animal from a familiar sound.','Make the conversation a tiny guessing game using one or two common animals.','["animals","game"]'::jsonb,'novice_low',true,237),
('everyday_038','Pet name','Imagine naming a new pet.','Ask what name the learner would give a pretend pet and what kind of pet it is.','["animals","names"]'::jsonb,'novice_low',true,238),
('everyday_039','Animal sizes','Compare a big animal and a small animal.','Ask which of two familiar animals is bigger or smaller.','["animals","comparison"]'::jsonb,'novice_low',true,239),
('everyday_040','Animal superpower','Imagine an ordinary animal with one silly superpower.','Ask the learner to choose a simple superpower for an animal. Keep it playful and age-appropriate.','["animals","imagination"]'::jsonb,'novice_low',true,240),
('everyday_041','School backpack','Talk about what belongs in a backpack.','Ask what one thing the learner puts in a school backpack.','["school","objects"]'::jsonb,'novice_low',true,241),
('everyday_042','Favorite subject','Talk about a school subject the learner likes.','Ask which class or subject the learner likes. Keep follow-ups small.','["school","preferences"]'::jsonb,'novice_low',true,242),
('everyday_043','Recess','Talk about what to do at recess.','Ask what the learner likes to do during recess or free time.','["school","activities"]'::jsonb,'novice_low',true,243),
('everyday_044','Pencil problem','Pretend a pencil broke or disappeared.','Ask what happened to the pencil or what the learner needs now.','["school","objects"]'::jsonb,'novice_low',true,244),
('everyday_045','Library book','Choose a book to borrow.','Ask what kind of book the learner would choose, using simple choices at low levels.','["school","books"]'::jsonb,'novice_low',true,245),
('everyday_046','Lunch table','Talk about sitting with friends at lunch.','Ask what the learner is eating or where something is on the table. Avoid asking for names of real classmates.','["school","food"]'::jsonb,'novice_low',true,246),
('everyday_047','Art project','Imagine drawing or painting something.','Ask what the learner wants to draw and what color to use first.','["school","colors"]'::jsonb,'novice_low',true,247),
('everyday_048','Science experiment','Talk about a harmless simple classroom experiment.','Ask what might happen when ice melts or another very simple safe observation.','["school","science"]'::jsonb,'novice_low',true,248),
('everyday_049','School bus','Talk about getting on a pretend school bus.','Ask where to sit or what the learner sees from the window. Do not ask for a real school or route.','["school","transportation"]'::jsonb,'novice_low',true,249),
('everyday_050','End of school day','Talk about what happens after school.','Ask what the learner likes to do after school.','["school","routine"]'::jsonb,'novice_low',true,250),
('everyday_051','Playground','Choose something to do at a playground.','Ask whether the learner wants the swings, slide, or another simple activity.','["play","choices"]'::jsonb,'novice_low',true,251),
('everyday_052','Bike ride','Imagine going for a bike ride.','Ask where the learner would like to ride in a generic safe place such as a park. Do not ask for real addresses.','["play","transportation"]'::jsonb,'novice_low',true,252),
('everyday_053','Ball game','Talk about throwing, kicking, or catching a ball.','Ask what kind of ball game the learner likes or what they can do with a ball.','["play","sports"]'::jsonb,'novice_low',true,253),
('everyday_054','Swimming pool','Talk about ordinary pool activities.','Ask what the learner likes to do in a pool. Keep it about activities, not bodies.','["play","sports"]'::jsonb,'novice_low',true,254),
('everyday_055','Building blocks','Build a pretend tower from blocks.','Ask what color block goes next or how tall the tower should be.','["play","colors"]'::jsonb,'novice_low',true,255),
('everyday_056','Board game','Talk about playing a simple board game.','Ask whether the learner likes winning, rolling dice, cards, or another simple part of a game.','["play","games"]'::jsonb,'novice_low',true,256),
('everyday_057','Hide and seek','Imagine a harmless game of hide and seek.','Ask where a toy could hide in a generic room. Do not ask where the child personally hides.','["play","location"]'::jsonb,'novice_low',true,257),
('everyday_058','Drawing a monster','Create a silly friendly monster.','Ask one feature at a time: color, number of eyes, size, or what it likes to eat.','["play","imagination"]'::jsonb,'novice_low',true,258),
('everyday_059','Toy store','Choose one pretend toy.','Ask the learner to choose between two toys, then talk about what it can do.','["play","choices"]'::jsonb,'novice_low',true,259),
('everyday_060','Rainy indoor game','Pick a game to play inside.','Ask what game or activity would be fun indoors on a rainy day.','["play","weather"]'::jsonb,'novice_low',true,260),
('everyday_061','Grocery store','Choose a few ordinary groceries.','Pretend to shop for one or two items. Ask what goes in the cart first.','["errands","food"]'::jsonb,'novice_low',true,261),
('everyday_062','Bakery','Choose bread or a simple baked treat.','Pretend to visit a bakery and ask what the learner wants. Keep the order very simple.','["errands","food"]'::jsonb,'novice_low',true,262),
('everyday_063','Clothing store','Choose a shirt, hat, or shoes.','Ask which color or clothing item the learner would choose.','["errands","clothing"]'::jsonb,'novice_low',true,263),
('everyday_064','Bookstore','Choose a book from a pretend store.','Ask what kind of book sounds fun, offering simple categories if needed.','["errands","books"]'::jsonb,'novice_low',true,264),
('everyday_065','Restaurant menu','Choose a simple meal from a pretend menu.','Ask what the learner would order. Recast their answer naturally as a polite request.','["errands","food"]'::jsonb,'novice_low',true,265),
('everyday_066','At the park','Talk about what is happening in a park.','Ask what the learner sees or wants to do in a generic park.','["places","activities"]'::jsonb,'novice_low',true,266),
('everyday_067','At the library','Talk about quiet activities at a library.','Ask what the learner would look for in a library. Do not ask for a real library name.','["places","books"]'::jsonb,'novice_low',true,267),
('everyday_068','At the doctor','Use a mild pretend checkup with no diagnosis.','Keep this to ordinary phrases such as hello, sit down, hand, head, or how do you feel. Do not give medical advice.','["places","body"]'::jsonb,'novice_low',true,268),
('everyday_069','At the dentist','Use a light pretend dental visit.','Talk about brushing teeth or opening the mouth for a pretend check. Keep it non-scary and non-medical.','["places","routine"]'::jsonb,'novice_low',true,269),
('everyday_070','Waiting in line','Talk about waiting for a turn somewhere ordinary.','Ask what the learner can see or do while waiting. Keep the location generic.','["places","actions"]'::jsonb,'novice_low',true,270),
('everyday_071','Car ride','Talk about things seen from a car window.','Ask what the learner might see from the window. Do not ask where they live or where they are going in real life.','["transportation","objects"]'::jsonb,'novice_low',true,271),
('everyday_072','Bus ride','Imagine taking a city bus somewhere generic.','Ask where to sit or what the learner sees. Keep destinations generic such as park or store.','["transportation","places"]'::jsonb,'novice_low',true,272),
('everyday_073','Train trip','Imagine a short train trip.','Ask what the learner would bring or look at from the train.','["transportation","travel"]'::jsonb,'novice_low',true,273),
('everyday_074','Airplane trip','Imagine flying somewhere for vacation.','Ask what the learner would pack or whether they like window seats. Do not ask for real itinerary details.','["transportation","travel"]'::jsonb,'novice_low',true,274),
('everyday_075','Walking to a park','Give simple pretend directions to a park.','Use left, right, near, and straight only as appropriate to the learner level. Keep all places fictional or generic.','["directions","places"]'::jsonb,'novice_low',true,275),
('everyday_076','Where is the toy?','Find a misplaced toy using location words.','Ask where the toy might be: on, under, beside, or in something.','["location","objects"]'::jsonb,'novice_low',true,276),
('everyday_077','Treasure map','Follow a very simple pretend treasure map.','Give or ask for one tiny direction at a time. Keep it clearly pretend.','["directions","game"]'::jsonb,'novice_low',true,277),
('everyday_078','Elevator buttons','Choose a floor in a pretend building.','Use numbers and simple up/down language. Keep the building generic.','["numbers","places"]'::jsonb,'novice_low',true,278),
('everyday_079','Crossing town','Choose between two generic places to visit.','Ask whether to go to the park, store, library, or another generic place, then discuss how to get there simply.','["directions","choices"]'::jsonb,'novice_low',true,279),
('everyday_080','Packing a bag','Decide what belongs in a bag for a short outing.','Ask what one useful item should go in the bag. Keep the destination generic.','["travel","objects"]'::jsonb,'novice_low',true,280),
('everyday_081','Happy moment','Talk about something that can make a person happy.','Ask what makes the learner happy using simple, non-personal examples if needed.','["feelings","preferences"]'::jsonb,'novice_low',true,281),
('everyday_082','Feeling tired','Talk about being tired after an ordinary day.','Ask what someone does when tired, such as rest, sit, or sleep.','["feelings","routine"]'::jsonb,'novice_low',true,282),
('everyday_083','Feeling excited','Talk about being excited for a harmless event.','Ask what kinds of things are exciting, using choices if needed.','["feelings","future"]'::jsonb,'novice_low',true,283),
('everyday_084','Feeling frustrated','Talk about a small everyday frustration such as a puzzle not working.','Use a mild pretend problem and ask what the learner could do next. Keep it supportive, not therapeutic.','["feelings","problem_solving"]'::jsonb,'novice_low',true,284),
('everyday_085','Favorite color','Talk about colors and objects.','Ask the learner''s favorite color, then connect it to one ordinary object.','["colors","preferences"]'::jsonb,'novice_low',true,285),
('everyday_086','Favorite number','Pick a favorite number and use it in a tiny game.','Ask for a favorite number or choose between two numbers, then use it naturally.','["numbers","preferences"]'::jsonb,'novice_low',true,286),
('everyday_087','Birthday cake','Design a pretend birthday cake without discussing personal dates.','Ask what flavor, color, or decoration the pretend cake should have. Do not ask for the learner''s birthday date.','["celebration","food"]'::jsonb,'novice_low',true,287),
('everyday_088','Weekend choice','Choose between two ordinary weekend activities.','Ask whether the learner would rather play outside, read, draw, cook, or another simple activity.','["time","preferences"]'::jsonb,'novice_low',true,288),
('everyday_089','Yesterday','Talk about one ordinary thing that happened yesterday.','At low levels offer choices. At higher levels invite one short past-tense detail.','["past","routine"]'::jsonb,'novice_low',true,289),
('everyday_090','Tomorrow','Talk about one ordinary thing someone might do tomorrow.','Ask one simple future-oriented question, scaled to the learner''s Spanish age.','["future","routine"]'::jsonb,'novice_low',true,290),
('everyday_091','Planting a seed','Imagine planting and watering a seed.','Ask what a seed needs or what might grow. Keep it concrete.','["nature","actions"]'::jsonb,'novice_low',true,291),
('everyday_092','Garden vegetables','Choose something to grow in a pretend garden.','Ask which fruit, vegetable, or flower the learner would grow.','["nature","food"]'::jsonb,'novice_low',true,292),
('everyday_093','Big tree','Talk about a tree, its size, leaves, and what might be under it.','Ask one simple observation question about a pretend tree.','["nature","description"]'::jsonb,'novice_low',true,293),
('everyday_094','Puddle jump','Imagine finding a puddle after rain.','Ask whether to go around it or jump over it, then follow the learner''s choice.','["nature","choices"]'::jsonb,'novice_low',true,294),
('everyday_095','Beach day','Imagine an ordinary day at the beach.','Ask what the learner would bring or do at a beach. Keep it about activities and objects.','["nature","activities"]'::jsonb,'novice_low',true,295),
('everyday_096','Picnic','Pack a simple pretend picnic.','Ask what food or object should go in the picnic basket.','["nature","food"]'::jsonb,'novice_low',true,296),
('everyday_097','Camping','Imagine a family-friendly camping trip.','Ask what ordinary item to bring or what someone might see outside. Keep it safe and generic.','["nature","travel"]'::jsonb,'novice_low',true,297),
('everyday_098','Moon and stars','Talk about seeing the moon or stars at night.','Ask what the learner can imagine seeing in the night sky. Keep it simple and factual or playful.','["nature","night"]'::jsonb,'novice_low',true,298),
('everyday_099','Silly invention','Invent a harmless machine that does one everyday job.','Ask what the machine should do. At low levels give two simple choices.','["imagination","actions"]'::jsonb,'novice_low',true,299),
('everyday_100','Mystery box','Imagine a box containing one ordinary object and guess what it is.','Run a tiny guessing conversation about an everyday object. Give simple clues and let the learner ask or guess.','["imagination","objects"]'::jsonb,'novice_low',true,300)
ON CONFLICT (key) DO UPDATE SET
  title = EXCLUDED.title,
  description = EXCLUDED.description,
  opening_instruction = EXCLUDED.opening_instruction,
  target_domains = EXCLUDED.target_domains,
  min_level = EXCLUDED.min_level,
  enabled = EXCLUDED.enabled,
  sort_order = EXCLUDED.sort_order;

-- The consolidator may suggest a scenario_key in the next lesson plan.
-- That was useful when the scenario itself was the curriculum, but it causes
-- the same setup to repeat now that conversation variety is a separate concern.
-- Keep all the useful plan material — target words, structures, review words,
-- callback hooks and coach notes — and let the scenario rotate independently.
UPDATE spanish_lesson_plans
   SET plan = plan - 'scenario_key'
 WHERE used_by_session IS NULL
   AND plan ? 'scenario_key';

CREATE OR REPLACE FUNCTION spanish_strip_planned_scenario()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF NEW.plan IS NOT NULL THEN
    NEW.plan := NEW.plan - 'scenario_key';
  END IF;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS spanish_strip_planned_scenario_trg ON spanish_lesson_plans;
CREATE TRIGGER spanish_strip_planned_scenario_trg
BEFORE INSERT OR UPDATE OF plan ON spanish_lesson_plans
FOR EACH ROW
EXECUTE FUNCTION spanish_strip_planned_scenario();

-- The browser already starts a normal conversation with scenario_key
-- 'free-talk'. Replace that generic key at INSERT time with the scenario this
-- learner has gone longest without seeing. NULL last_used sorts first, so all
-- 100 topics are used once before any is repeated. After that, the oldest one
-- comes back around. random() only breaks ties among never-used topics, making
-- each learner's order different without sacrificing the no-repeat property.
CREATE OR REPLACE FUNCTION spanish_choose_everyday_scenario()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
  chosen text;
BEGIN
  IF NEW.scenario_key = 'free-talk' THEN
    SELECT s.key
      INTO chosen
      FROM spanish_scenarios s
      LEFT JOIN LATERAL (
        SELECT MAX(ss.started_at) AS last_used
          FROM spanish_sessions ss
         WHERE ss.user_id = NEW.user_id
           AND ss.scenario_key = s.key
      ) used ON true
     WHERE s.enabled = true
       AND s.key LIKE 'everyday\_%' ESCAPE '\'
     ORDER BY used.last_used ASC NULLS FIRST, random()
     LIMIT 1;

    IF chosen IS NOT NULL THEN
      NEW.scenario_key := chosen;
    END IF;
  END IF;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS spanish_choose_everyday_scenario_trg ON spanish_sessions;
CREATE TRIGGER spanish_choose_everyday_scenario_trg
BEFORE INSERT ON spanish_sessions
FOR EACH ROW
EXECUTE FUNCTION spanish_choose_everyday_scenario();
