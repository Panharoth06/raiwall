package bot

// challengePageScript drives the passive verification flow: capability check,
// background proof-of-work, success confirmation, automatic return, and an
// actionable retry state on failure.
const challengePageScript = `
    (function () {
      'use strict';

      var challenge = {{.ChallengeJSON}};
      var redirectURL = {{.RedirectURL}};
      var verifyPath = '/.raiwall/challenge/verify';
      var maxNumber = Math.max(1000, Number(challenge && challenge.maxNumber) || 50000);
      var batchSize = 500;
      var body = document.body;
      var titleEl = document.getElementById('title');
      var messageEl = document.getElementById('message');
      var announcer = document.getElementById('announcer');
      var meter = document.getElementById('meter');
      var fill = document.getElementById('progress');
      var destination = document.getElementById('destination');
      var retryBtn = document.getElementById('retry');
      var hint = document.getElementById('hint');
      var stopped = false;
      var submitting = false;

      function setProgress(percent) {
        var value = Math.max(0, Math.min(100, Math.round(percent)));
        fill.style.transform = 'scaleX(' + (value / 100) + ')';
        meter.setAttribute('aria-valuenow', String(value));
      }

      function setState(state, title, message) {
        body.setAttribute('data-state', state);
        titleEl.textContent = title;
        messageEl.textContent = message;
        announcer.textContent = title + '. ' + message;
      }

      function fail(title, message) {
        if (stopped) return;
        stopped = true;
        setState('error', title, message);
        meter.hidden = true;
        destination.hidden = true;
        hint.hidden = false;
        retryBtn.hidden = false;
        retryBtn.focus();
      }

      function hex(buffer) {
        var bytes = new Uint8Array(buffer);
        var out = '';
        for (var i = 0; i < bytes.length; i++) {
          out += bytes[i].toString(16).padStart(2, '0');
        }
        return out;
      }

      function later(ms) {
        return new Promise(function (resolve) { setTimeout(resolve, ms); });
      }

      function complete(number) {
        stopped = true;
        setProgress(100);
        setState('done', 'Verification complete', 'Your browser passed the security check. Redirecting now.');
        destination.hidden = false;
        meter.hidden = true;
        window.setTimeout(function () {
          submitSolution({
            algorithm: challenge.algorithm,
            challenge: challenge.challenge,
            number: number,
            salt: challenge.salt,
            signature: challenge.signature
          });
        }, 750);
      }

      function submitSolution(payload) {
        if (submitting) return;
        submitting = true;

        fetch(verifyPath, {
          method: 'POST',
          credentials: 'same-origin',
          headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
          body: JSON.stringify({ payload: payload, redirect: redirectURL })
        }).then(function (response) {
          if (!response.ok) throw new Error('verification rejected');
          return response.json();
        }).then(function (data) {
          if (!data || data.success !== true) throw new Error('verification rejected');
          window.location.replace(data.redirect || redirectURL);
        }).catch(function () {
          submitting = false;
          stopped = false;
          fail('Verification expired', 'The security check could not be confirmed. Retry to generate a new challenge.');
        });
      }

      function solve() {
        if (!window.crypto || !window.crypto.subtle || !window.TextEncoder || !window.Promise) {
          fail('Browser not supported', 'This browser cannot run the security check. Update to a current version of Chrome, Safari, Firefox, or Edge.');
          return;
        }

        var encoder = new TextEncoder();
        var salt = String(challenge && challenge.salt || '');
        var target = String(challenge && challenge.challenge || '');

        if (!salt || !target) {
          fail('Verification unavailable', 'The security challenge could not be loaded. Retry to request a new one.');
          return;
        }

        function runBatch(start) {
          if (stopped) return;
          var end = Math.min(start + batchSize, maxNumber);
          var probes = [];

          for (var i = start; i < end; i++) {
            probes.push(
              window.crypto.subtle.digest('SHA-256', encoder.encode(salt + i)).then(function (buffer) {
                return hex(buffer);
              })
            );
          }

          Promise.all(probes).then(function (hashes) {
            for (var j = 0; j < hashes.length; j++) {
              if (hashes[j] === target) {
                complete(start + j);
                return;
              }
            }
            setProgress((end / maxNumber) * 100);
            if (end < maxNumber) {
              later(0).then(function () { runBatch(end); });
            } else {
              fail('Verification timed out', 'The security check did not finish in time. Retry to generate a new challenge.');
            }
          }).catch(function () {
            fail('Verification failed', 'The browser could not complete the security check. Retry to generate a new challenge.');
          });
        }

        runBatch(0);
      }

      retryBtn.addEventListener('click', function () {
        window.location.reload();
      });

      // Let the initial checking state paint before starting the CPU work.
      window.requestAnimationFrame(function () {
        window.setTimeout(solve, 150);
      });
    })();
`
