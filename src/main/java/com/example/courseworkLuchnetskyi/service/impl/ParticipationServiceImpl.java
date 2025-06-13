package com.example.courseworkLuchnetskyi.service.impl;

import com.example.courseworkLuchnetskyi.dto.request.ParticipationRequestDto;
import com.example.courseworkLuchnetskyi.dto.response.ParticipationResponseDto;
import com.example.courseworkLuchnetskyi.mapper.ParticipationMapper;
import com.example.courseworkLuchnetskyi.model.Participation;
import com.example.courseworkLuchnetskyi.repository.ParticipationRepository;
import com.example.courseworkLuchnetskyi.repository.TeamRepository;
import com.example.courseworkLuchnetskyi.repository.TournamentRepository;
import com.example.courseworkLuchnetskyi.service.ParticipationService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@RequiredArgsConstructor
public class ParticipationServiceImpl implements ParticipationService {

    private final ParticipationRepository participationRepository;
    private final TeamRepository teamRepository;
    private final TournamentRepository tournamentRepository;
    private final ParticipationMapper mapper;

    @Override
    public ParticipationResponseDto addParticipation(ParticipationRequestDto dto) {
        Participation participation = mapper.toEntity(dto);

        participation.setTeam(teamRepository.findById(dto.teamId())
                .orElseThrow(() -> new RuntimeException("Team not found")));

        participation.setTournament(tournamentRepository.findById(dto.tournamentId())
                .orElseThrow(() -> new RuntimeException("Tournament not found")));

        return mapper.toDto(participationRepository.save(participation));
    }

    @Override
    public List<ParticipationResponseDto> getTeamsByTournament(Long tournamentId) {
        return participationRepository.findByTournamentId(tournamentId).stream()
                .map(mapper::toDto)
                .toList();
    }

    @Override
    public List<ParticipationResponseDto> getTournamentsByTeam(Long teamId) {
        return participationRepository.findByTeamId(teamId).stream()
                .map(mapper::toDto)
                .toList();
    }
}
