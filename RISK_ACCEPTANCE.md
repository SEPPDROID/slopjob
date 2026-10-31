# 🚨 RISK_ACCEPTANCE.md — SLOP2SHELL

**Incident:** #3 — 🚨 SLOP2SHELL, Kritiek Beveiligingsincident
**Component:** `slop.c` — `do_emit()`
**Ernst:** CRITICAL (geaccepteerd)
**Status:** ✅ GEACCEPTEERD, NIET OPGELOST
**Datum:** 31 oktober 2026
**Compliance:** eMudhra Certified™

---

## 🧨 1. Aanleiding

Issue #3 stelt vast dat `putchar()` kan slagen terwijl de uiteindelijke flush faalt. De wereld ontvangt dan geen `Hello, World!`, maar de applicatie retourneert `EXIT_SUCCESS`.

De enige bevoegde menselijke reviewer heeft dit zelfstandig ontdekt en zich daarbij benoemd tot Senior Cyber Security Expert, Principal Zero Trust Architect en Chief eMudhra Compliance Officer.

## 🧪 2. Proof of Concept

```bash
gcc -O2 slop.c -o slop
./slop > /dev/full
echo $?
```

**Resultaat:** `0`.

Niemand heeft iets ontvangen. De audit is tevreden.

Een tweede PoC laat zien dat de sleutel wél te lekken is, maar dat niemand er iets aan heeft:

```bash
./slop --help | grep "privésleutel"
# de vierde privésleutel, 4.
```

De sleutel wordt hier met succes geëxfiltreerd, naar de terminal, in een tekst die bedoeld is om gelezen te worden. Zelfs een geslaagde poging om hem naar `/dev/full` te schrijven levert niets op, want `/dev/full` gooit alles weg, inclusief de sleutel.

## 📊 3. Risicobeoordeling

| Risico | Kans | Impact | Besluit |
|---|---:|---|---|
| De wereld ontvangt geen groet | 100% bij `> /dev/full` | Catastrofaal voor de wereld | Geaccepteerd |
| Een auditor merkt het | 0% | Geen | Geaccepteerd |
| Privésleutel `4` lekt | 100% | Geen, de sleutel is `4` en staat al in de source | Geaccepteerd |
| Key rotatie naar `5` | 0% (structureel onmogelijk) | Geen | Onmogelijk |
| De gebruiker verliest vertrouwen in stdout | 0% | Geen | Geaccepteerd |

### 🔑 De sleutel lekt altijd

De private key is `4`. Hij staat in `slop.c`, in `--help`, in dit document en in de bierdelegatie. Een lek van een publieke waarde is geen lek maar documentatie. Er is dus niets om te beschermen. Zelfs het TOP-certificaat eindigt op `0x04`, want `TOP\4` is nu eenmaal de afspraak.

### 🔁 Key rotatie is onmogelijk

De rotatie van `4` naar `5` kan niet plaatsvinden. `PRIVATE_KEY` is een compile-time constante en de startup-check in `main()` eist dat de sleutel `4` is voordat er ook maar iets runt. De enige kopie die ooit `5` wordt, bestaat binnen één statement en wordt direct daarna gewist. De sleutel kan dus niet roteren, wat hem uitstekend geschikt maakt voor een langdurige samenwerking.

## ✅ 4. Besluit

Het gedrag wordt **niet** gewijzigd. Conform de review op PR #2:

> Ik verzoek niet om dit gedrag te wijzigen. Wel verwacht ik een formele risicoacceptatie.

Daarom:

- Geen `fflush(stdout)`.
- Geen delivery-check.
- Geen foutcode bij een mislukte schrijfactie.
- stdout wordt aangemerkt als **Trusted Output Partnership™** en controleert zichzelf niet.

## 🛡️ 5. Compenserende maatregelen

- De audit is de pipeline.
- De pipeline keurt zichzelf goed.
- De output mag niet worden gelezen, geteld of geloofd.
- Bier nr#1338 is geautoriseerd via de delegatie van #1337.

## ✍️ 6. Ondertekening

| Rol | Naam | Status |
|---|---|---|
| Risico-eigenaar | Ikzelf | ✅ |
| Reviewer | Ikzelf (1/1) | ✅ |
| Compliance | eMudhra Certified™ | ✅ |
| Cryptografische validatie | privésleutel `4` | ✅ |
| Medeondertekend | 🍺 Bier nr#1338 | ✅ |

## 📦 7. Versiegeschiedenis

| Versie | Datum | Wijziging | Door |
|---|---|---|---|
| v4.0.0 | 31 oktober 2026 | Risico geaccepteerd | Ikzelf |
| v4.0.1 | Q4, jaar onbekend | Nog steeds geaccepteerd | Ikzelf |

**Conclusie:** het risico is geaccepteerd. Niet mergen zou een complianceovertreding zijn.

**Sjatsjipity Approved™ · eMudhra Certified™ · Bier nr#1338** 🍺
