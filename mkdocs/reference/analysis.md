# Analysis, Visualisation, and Stress Tests

## Analysis

```bash
dead-drop analyse suspicious.png --deep
dead-drop compare before.png after.png
```

A report separates:

- Facts, such as the format, the size, and bytes after a PNG `IEND`.
- Measurements, such as byte entropy, MSE, PSNR, SSIM, and LSB counts.
- Heuristics, such as a chi-square statistic on least-significant bits.
- Detections of a known Dead Drop marker when those bytes are present in the clear.
- Unsupported conclusions. A statistic is never reported as proof.

Image analysis can emit channel LSB chi-square values, histograms, and bit planes. Audio analysis covers sample LSB behaviour, SNR, and a waveform picture. Text analysis lists trailing whitespace, tab and space runs, zero-width characters,
and a normalisation note.

## Pictures

```bash
dead-drop visualise image.png --type bit-plane --channel red --bit 0 --output plane.png
dead-drop visualise image.png --type histogram --output histogram.png
dead-drop visualise tone.wav --type waveform --output wave.png
```

Outputs are PNG, SVG, self-contained HTML, or JSON, chosen from `--type` and the output suffix. Benchmark tables also write CSV and Markdown through `--output`.

```bash
dead-drop algorithms compare --carrier image.png --payload sample.bin --output bench.csv
```

The table includes capacity, a fit check, elapsed time, and peak traced memory. It does not include keys or payload bytes.

## Stress Tests

```bash
dead-drop stress-test image.png
```

Image tests rewrite, resize, rotate, and JPEG-convert a temporary copy. The original file is not opened for writing. Each row records the transform, whether a PNG LSB extract still returned an envelope, and the failure type when it did not.
Resize, rotation, and JPEG conversion are expected to destroy pixel LSB payloads. That result is a measurement of this implementation, not a universal claim about every steganographic scheme.

Audio and text transforms (line endings, trimming, normalisation, resampling, gain, noise) belong to the same report shape: parameters, carrier validity, detection, reconstruction, authentication, and the failure reason. Distributed loss,
duplicate fragments, mixed sets, and wrong passwords are covered by the recovery and share commands and by the test suite. A wrong password is an authentication failure, not a recovered file.

## Algorithm Properties

`dead-drop algorithms info png-lsb` prints the identifier, version, formats, capacity formula, whether extraction needs a key or extra metadata, placement behaviour, transformation tolerance, visualisations, distortion metrics, and forensic
tests. Those strings are the engine's own description of what it implements.
