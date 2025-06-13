package com.example.courseworkLuchnetskyi.mapper;

import com.example.courseworkLuchnetskyi.dto.request.ParticipationRequestDto;
import com.example.courseworkLuchnetskyi.dto.response.ParticipationResponseDto;
import com.example.courseworkLuchnetskyi.dto.response.TeamResponseDto;
import com.example.courseworkLuchnetskyi.dto.response.TournamentResponseDto;
import com.example.courseworkLuchnetskyi.model.Participation;
import com.example.courseworkLuchnetskyi.model.Team;
import com.example.courseworkLuchnetskyi.model.Tournament;
import java.time.LocalDate;
import javax.annotation.processing.Generated;
import org.springframework.stereotype.Component;

@Generated(
    value = "org.mapstruct.ap.MappingProcessor",
    date = "2025-06-12T13:09:29+0300",
    comments = "version: 1.5.5.Final, compiler: javac, environment: Java 17.0.13 (Amazon.com Inc.)"
)
@Component
public class ParticipationMapperImpl implements ParticipationMapper {

    @Override
    public Participation toEntity(ParticipationRequestDto dto) {
        if ( dto == null ) {
            return null;
        }

        Participation participation = new Participation();

        return participation;
    }

    @Override
    public ParticipationResponseDto toDto(Participation participation) {
        if ( participation == null ) {
            return null;
        }

        Long id = null;
        TeamResponseDto team = null;
        TournamentResponseDto tournament = null;

        id = participation.getId();
        team = teamToTeamResponseDto( participation.getTeam() );
        tournament = tournamentToTournamentResponseDto( participation.getTournament() );

        ParticipationResponseDto participationResponseDto = new ParticipationResponseDto( id, team, tournament );

        return participationResponseDto;
    }

    protected TeamResponseDto teamToTeamResponseDto(Team team) {
        if ( team == null ) {
            return null;
        }

        Long id = null;
        String name = null;
        String city = null;

        id = team.getId();
        name = team.getName();
        city = team.getCity();

        TeamResponseDto teamResponseDto = new TeamResponseDto( id, name, city );

        return teamResponseDto;
    }

    protected TournamentResponseDto tournamentToTournamentResponseDto(Tournament tournament) {
        if ( tournament == null ) {
            return null;
        }

        Long id = null;
        String name = null;
        LocalDate startDate = null;
        LocalDate endDate = null;
        String location = null;

        id = tournament.getId();
        name = tournament.getName();
        startDate = tournament.getStartDate();
        endDate = tournament.getEndDate();
        location = tournament.getLocation();

        TournamentResponseDto tournamentResponseDto = new TournamentResponseDto( id, name, startDate, endDate, location );

        return tournamentResponseDto;
    }
}
