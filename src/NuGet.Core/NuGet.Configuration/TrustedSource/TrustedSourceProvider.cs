// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Collections.Generic;
using System.Linq;
using NuGet.Common;
using NuGet.Shared;

namespace NuGet.Configuration
{
    public class TrustedSourceProvider : ITrustedSourceProvider
    {
        private ISettings _settings;

        public TrustedSourceProvider(ISettings settings)
        {
            _settings = settings;
        }

        public IEnumerable<TrustedSource> LoadTrustedSources()
        {
            var trustedSources = new List<TrustedSource>();
            var trustedSourceNames = new HashSet<string>();
            _settings.GetAllSubsections(ConfigurationConstants.TrustedSources)
                .ForEach(s => trustedSourceNames.Add(s));

            foreach (var trustedSourceName in trustedSourceNames)
            {
                var trustedSource = LoadTrustedSource(trustedSourceName);

                if (trustedSource != null)
                {
                    trustedSources.Add(trustedSource);
                }
            }

            return trustedSources;
        }

        public TrustedSource LoadTrustedSource(string packageSourceName)
        {
            TrustedSource trustedSource = null;
            var settingValues = _settings.GetNestedSettingValues(ConfigurationConstants.TrustedSources, packageSourceName);

            if (settingValues?.Count > 0)
            {
                trustedSource = new TrustedSource(packageSourceName);
                foreach (var settingValue in settingValues)
                {
                    if (string.Equals(settingValue.Key, ConfigurationConstants.ServiceIndex, StringComparison.OrdinalIgnoreCase))
                    {
                        trustedSource.ServiceIndex = settingValue.Value;
                    }
                    else
                    {
                        var fingerprint = settingValue.Key;
                        var subjectName = settingValue.Value;
                        var algorithm = HashAlgorithmName.SHA256;

                        if (settingValue.AdditionalData.TryGetValue(ConfigurationConstants.FingerprintAlgorithm, out var algorithmString) &&
                            CryptoHashUtility.GetHashAlgorithmName(algorithmString) != HashAlgorithmName.Unknown)
                        {
                            algorithm = CryptoHashUtility.GetHashAlgorithmName(algorithmString);
                        }

                        trustedSource.Certificates.Add(new CertificateTrustEntry(fingerprint, subjectName, algorithm, settingValue.Priority));
                    }
                }
            }

            return trustedSource;
        }

        public void SaveTrustedSources(IEnumerable<TrustedSource> sources)
        {
            WriteTrustedSources(sources);
        }

        public void SaveTrustedSource(TrustedSource source)
        {
            var existingSources = LoadTrustedSources().ToList();
            SaveTrustedSource(source, existingSources);
        }

        private void SaveTrustedSource(TrustedSource source, IList<TrustedSource> existingSources)
        {
            var matchingSource = existingSources
                .Where(s => string.Equals(s.SourceName, source.SourceName, StringComparison.OrdinalIgnoreCase))
                .FirstOrDefault();

            var settingValues = new List<SettingValue>();

            foreach (var cert in source.Certificates)
            {
                // use existing priority if present
                var priority = matchingSource?.Certificates.FirstOrDefault(c => c.Fingerprint == cert.Fingerprint)?.Priority ?? cert.Priority;

                // cant save to machine wide settings
                var settingValue = new SettingValue(cert.Fingerprint, cert.SubjectName, isMachineWide: false, priority: priority);

                settingValue.AdditionalData.Add(ConfigurationConstants.FingerprintAlgorithm, cert.FingerprintAlgorithm.ToString());
                settingValues.Add(settingValue);
            }

            if (!string.IsNullOrEmpty(source.ServiceIndex))
            {
                // TODO pass priority
                var settingValue = new SettingValue(ConfigurationConstants.ServiceIndex, source.ServiceIndex, isMachineWide: false);
                settingValues.Add(settingValue);
            }

            if (matchingSource != null)
            {
                existingSources.Remove(matchingSource);
            }

            existingSources.Add(source);
            _settings.DeleteSections(ConfigurationConstants.TrustedSources);
            SaveTrustedSources(existingSources);
        }

        public void DeleteTrustedSource(string sourceName)
        {
            var existingSources = LoadTrustedSources().AsList();
            var matchingSource = existingSources
                .Where(s => string.Equals(s.SourceName, sourceName, StringComparison.OrdinalIgnoreCase))
                .FirstOrDefault();

            if (matchingSource != null)
            {
                existingSources.Remove(matchingSource);
                WriteTrustedSources(existingSources);
            }
        }

        private void WriteTrustedSources(IEnumerable<TrustedSource> sources)
        {
            _settings.DeleteSections(ConfigurationConstants.TrustedSources);
            foreach (var source in sources)
            {
                var settingValues = new List<SettingValue>();

                foreach (var cert in source.Certificates)
                {
                    var settingValue = new SettingValue(cert.Fingerprint, cert.SubjectName, isMachineWide: false, priority: cert.Priority);

                    settingValue.AdditionalData.Add(ConfigurationConstants.FingerprintAlgorithm, cert.FingerprintAlgorithm.ToString());
                    settingValues.Add(settingValue);
                }

                if (!string.IsNullOrEmpty(source.ServiceIndex))
                {
                    // TODO pass priority
                    var settingValue = new SettingValue(ConfigurationConstants.ServiceIndex, source.ServiceIndex, isMachineWide: false);
                    settingValues.Add(settingValue);
                }

                _settings.SetNestedSettingValues(ConfigurationConstants.TrustedSources, source.SourceName, settingValues);
            }
        }
    }
}
